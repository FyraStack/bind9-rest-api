use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::TSigner;
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone)]
pub enum DnsError {
    Protocol(String),
    Parse(String),
    Response(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            DnsError::Parse(msg) => write!(f, "Parse error: {msg}"),
            DnsError::Response(msg) => write!(f, "Response error: {msg}"),
        }
    }
}

impl std::error::Error for DnsError {}

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Clone)]
pub struct DnsClient {
    addr: DnsAddress,
    signer: Option<TSigner>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsAddress {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

impl DnsClient {
    pub fn new(
        addr: impl TryInto<DnsAddress>,
        key_name: impl AsRef<str>,
        key: impl Into<Vec<u8>>,
        algorithm: TsigAlgorithm,
    ) -> Result<Self> {
        Ok(DnsClient {
            addr: addr
                .try_into()
                .map_err(|_| DnsError::Parse("Invalid address".to_string()))?,
            signer: Some(
                TSigner::new(
                    key.into(),
                    algorithm,
                    Name::from_ascii(key_name.as_ref())
                        .map_err(|e| DnsError::Parse(e.to_string()))?,
                    60,
                )
                .map_err(|e| DnsError::Parse(e.to_string()))?,
            ),
        })
    }

    async fn connect(&self) -> Result<Client<TokioRuntimeProvider>> {
        match &self.addr {
            DnsAddress::Udp(addr) => {
                let mut builder = UdpClientStream::builder(*addr, TokioRuntimeProvider::new());
                if let Some(signer) = &self.signer {
                    builder = builder.with_signer(Some(signer.clone()));
                }
                let stream = builder.build();
                let (client, bg) = Client::from_sender(stream);
                tokio::spawn(bg);
                Ok(client)
            }
            DnsAddress::Tcp(addr) => {
                let (stream_future, sender) =
                    TcpClientStream::new(*addr, None, None, TokioRuntimeProvider::new());
                let stream = stream_future
                    .await
                    .map_err(|e| DnsError::Protocol(e.to_string()))?;
                let mut multiplexer = DnsMultiplexer::new(stream, sender);
                if let Some(signer) = &self.signer {
                    multiplexer = multiplexer.with_signer(signer.clone());
                }
                let (client, bg) = Client::from_sender(multiplexer);
                tokio::spawn(bg);
                Ok(client)
            }
        }
    }

    /// Set (replace) a PTR record at `name` in `zone`.
    /// An empty `ptr_target` deletes the record.
    pub async fn set_ptr(&self, name: &str, ttl: u32, ptr_target: &str, zone: &str) -> Result<()> {
        let owner = Name::from_str_relaxed(name).map_err(|e| DnsError::Parse(e.to_string()))?;
        let zone_name = Name::from_str_relaxed(zone).map_err(|e| DnsError::Parse(e.to_string()))?;

        let mut client = self.connect().await?;

        // Delete existing PTR at this owner
        let delete = Record::update0(owner.clone(), 0, RecordType::PTR);
        let result = client
            .delete_rrset(delete, zone_name.clone())
            .await
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        if result.response_code != ResponseCode::NoError {
            return Err(DnsError::Response(result.response_code.to_string()));
        }

        // If no target, we're done (delete only)
        if ptr_target.is_empty() {
            return Ok(());
        }

        // Add new PTR record
        let mut rrset = RecordSet::with_ttl(owner, RecordType::PTR, ttl);
        rrset.add_rdata(RData::PTR(PTR(
            Name::from_str_relaxed(ptr_target).map_err(|e| DnsError::Parse(e.to_string()))?
        )));

        let result = client
            .append(rrset, zone_name, false)
            .await
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        if result.response_code != ResponseCode::NoError {
            return Err(DnsError::Response(result.response_code.to_string()));
        }
        Ok(())
    }

    /// List PTR records at `name`. Returns the PTR targets.
    pub async fn list_ptrs(&self, name: &str) -> Result<Vec<String>> {
        let owner = Name::from_str_relaxed(name).map_err(|e| DnsError::Parse(e.to_string()))?;

        let mut client = self.connect().await?;
        let response = client
            .query(owner.clone(), DNSClass::IN, RecordType::PTR)
            .await
            .map_err(|e| DnsError::Protocol(e.to_string()))?;
        if response.response_code != ResponseCode::NoError
            && response.response_code != ResponseCode::NXDomain
        {
            return Err(DnsError::Response(response.response_code.to_string()));
        }

        let mut out = Vec::new();
        for record in response.answers.iter() {
            if record.record_type() != RecordType::PTR || record.name != owner {
                continue;
            }
            if let RData::PTR(ptr) = &record.data {
                out.push(strip_trailing_dot(&ptr.0.to_utf8()));
            }
        }
        Ok(out)
    }
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

impl TryFrom<&str> for DnsAddress {
    type Error = ();

    fn try_from(url: &str) -> std::result::Result<Self, Self::Error> {
        let (host, is_tcp) = if let Some(host) = url.strip_prefix("udp://") {
            (host, false)
        } else if let Some(host) = url.strip_prefix("tcp://") {
            (host, true)
        } else {
            (url, false)
        };
        let (host, port) = if let Some(host) = host.strip_prefix('[') {
            let (host, maybe_port) = host.rsplit_once(']').ok_or(())?;
            (
                host,
                maybe_port
                    .strip_prefix(':')
                    .ok_or(())?
                    .parse::<u16>()
                    .map_err(|_| ())?,
            )
        } else {
            let (host, port) = host.rsplit_once(':').ok_or(())?;
            (host, port.parse::<u16>().map_err(|_| ())?)
        };
        let addr: SocketAddr = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|_| ())?
            .next()
            .ok_or(())?;
        if is_tcp {
            Ok(DnsAddress::Tcp(addr))
        } else {
            Ok(DnsAddress::Udp(addr))
        }
    }
}

impl TryFrom<&String> for DnsAddress {
    type Error = ();

    fn try_from(url: &String) -> std::result::Result<Self, Self::Error> {
        (url.as_str()).try_into()
    }
}

impl TryFrom<String> for DnsAddress {
    type Error = ();

    fn try_from(url: String) -> std::result::Result<Self, Self::Error> {
        (url.as_str()).try_into()
    }
}
