//! The transport seam: how a [`super::Node`] gets datagrams onto and off the network.
//!
//! [`UdpTransport`] is two real UDP sockets (SPEC 2.1) plus, once
//! [`Transport::open_relay`] is called, a third socket for a [`RelayLink`]: datagrams to
//! synthetic peer endpoints (`0.0.0.(k+1)`) are wrapped and sent to the relay, and relayed
//! datagrams come back out of [`Transport::recv`] as if they had arrived on the socket
//! they were addressed to. See the module documentation of [`crate::io`].

use std::fmt;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub use crate::nat::traversal::Socket;
use crate::relay::{is_synthetic, Received, RelayEvent, RelayLink, WrapError};
use crate::types::{Endpoint, Instant, Outgoing};
use crate::wire::MAX_DATAGRAM;

/// One received datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// The local socket it arrived on (or, for a relayed datagram, the local socket it was
    /// addressed to).
    pub socket: Socket,
    pub from: Endpoint,
    pub bytes: Vec<u8>,
}

/// Something the transport reports from [`Transport::poll`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEvent {
    /// The relay link changed state.
    Relay(RelayEvent),
    /// A line for the log.
    Log(String),
}

/// A transport failure. [`fmt::Display`] is a plain-English sentence.
#[derive(Debug)]
pub enum TransportError {
    /// The port is taken by another program.
    PortInUse(u16),
    /// Any other failure to bind.
    Bind { port: u16, detail: String },
    /// The socket is not open (closed, or never bound).
    NotOpen(Socket),
    /// A send or receive failed.
    Io(std::io::Error),
    /// This transport has no relay link (or cannot have one).
    NoRelay,
    /// A datagram could not be relayed.
    Relay(WrapError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortInUse(p) => write!(f, "UDP port {p} is in use; is another game running?"),
            Self::Bind { port, detail } => {
                write!(f, "Could not listen on UDP port {port}: {detail}")
            }
            Self::NotOpen(Socket::Discovery) => write!(f, "The discovery socket is closed"),
            Self::NotOpen(Socket::Game) => write!(f, "The game socket is closed"),
            Self::Io(e) => write!(f, "Network error: {e}"),
            Self::NoRelay => write!(f, "No relay is in use"),
            Self::Relay(e) => write!(f, "Could not relay a datagram: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Where a [`super::Node`] sends and receives. Every method must return promptly.
pub trait Transport {
    /// The local port of a socket, if it is open.
    fn local_port(&self, socket: Socket) -> Option<u16>;

    /// Send one datagram from `socket`.
    fn send(&mut self, socket: Socket, out: &Outgoing) -> Result<(), TransportError>;

    /// The next pending datagram, without blocking; `Ok(None)` when there is none.
    fn recv(&mut self, now: Instant) -> Result<Option<Datagram>, TransportError>;

    /// SPEC 3.7: close the game socket and immediately bind the same port again, so the
    /// game's first datagrams leave from the port the router already mapped.
    fn rebind_game(&mut self) -> Result<(), TransportError>;

    /// Stop discovery (the lobby is over).
    fn close_discovery(&mut self);

    /// Run the transport's own timers (a relay's hello retries and keepalives), and hand
    /// over what happened since the last call.
    fn poll(&mut self, _now: Instant) -> Vec<TransportEvent> {
        Vec::new()
    }

    /// When [`Transport::poll`] next has work.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Start using a relay link (a fresh [`RelayLink::host`] or [`RelayLink::guest`]).
    fn open_relay(&mut self, _link: RelayLink) -> Result<(), TransportError> {
        Err(TransportError::NoRelay)
    }

    /// The relay link, if one is open.
    fn relay_link(&self) -> Option<&RelayLink> {
        None
    }

    /// The largest datagram (CRC included) that may be sent to `to`: smaller for a relayed
    /// peer (the relay's `max_payload`).
    fn max_datagram_to(&self, _to: Endpoint) -> usize {
        MAX_DATAGRAM
    }

    /// Block for at most `timeout`, returning early when a datagram may be waiting.
    fn wait(&mut self, timeout: Duration) {
        std::thread::sleep(timeout);
    }
}

fn bind(ip: Ipv4Addr, port: u16) -> Result<UdpSocket, TransportError> {
    let sock = UdpSocket::bind(SocketAddrV4::new(ip, port)).map_err(|e| match e.kind() {
        ErrorKind::AddrInUse => TransportError::PortInUse(port),
        _ => TransportError::Bind {
            port,
            detail: e.to_string(),
        },
    })?;
    sock.set_nonblocking(true).map_err(TransportError::Io)?;
    Ok(sock)
}

fn send_raw(sock: &UdpSocket, out: &Outgoing) -> Result<(), TransportError> {
    match sock.send_to(&out.bytes, out.to) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(TransportError::Io(e)),
    }
}

/// Read one IPv4 datagram from a non-blocking socket. Windows reports an ICMP "port
/// unreachable" for an earlier send as a connection reset on receive; that is skipped
/// (2.5), as are datagrams too large for the buffer.
fn recv_raw(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> Result<Option<(Endpoint, Vec<u8>)>, TransportError> {
    loop {
        match sock.recv_from(buf) {
            Ok((n, SocketAddr::V4(from))) => {
                if n > MAX_DATAGRAM {
                    continue;
                }
                let bytes = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
                return Ok(Some((from, bytes)));
            }
            Ok((_, SocketAddr::V6(_))) => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == ErrorKind::TimedOut => return Ok(None),
            Err(e) if e.kind() == ErrorKind::ConnectionReset => continue,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // WSAEMSGSIZE: larger than the buffer.
            Err(e) if e.raw_os_error() == Some(10040) => continue,
            Err(e) => return Err(TransportError::Io(e)),
        }
    }
}

/// Two real UDP sockets, discovery / lobby and game (SPEC 2.1), and an optional relay
/// socket. IPv4 only.
#[derive(Debug)]
pub struct UdpTransport {
    ip: Ipv4Addr,
    discovery: Option<UdpSocket>,
    game: Option<UdpSocket>,
    game_port: u16,
    turn: u8,
    buf: Vec<u8>,
    relay: Option<(UdpSocket, RelayLink)>,
    events: Vec<TransportEvent>,
}

impl UdpTransport {
    /// Bind the sockets on `ip`. `None` skips a socket; port 0 picks a free port. Port in
    /// use is reported, never shared (no address reuse, 2.1).
    pub fn bind(
        ip: Ipv4Addr,
        discovery_port: Option<u16>,
        game_port: Option<u16>,
    ) -> Result<Self, TransportError> {
        let discovery = match discovery_port {
            Some(p) => {
                let s = bind(ip, p)?;
                s.set_broadcast(true).map_err(TransportError::Io)?;
                Some(s)
            }
            None => None,
        };
        let game = match game_port {
            Some(p) => Some(bind(ip, p)?),
            None => None,
        };
        let game_port = match &game {
            Some(s) => s.local_addr().map_err(TransportError::Io)?.port(),
            None => 0,
        };
        Ok(Self {
            ip,
            discovery,
            game,
            game_port,
            turn: 0,
            buf: vec![0; MAX_DATAGRAM + 1],
            relay: None,
            events: Vec::new(),
        })
    }

    fn socket(&self, socket: Socket) -> Option<&UdpSocket> {
        match socket {
            Socket::Discovery => self.discovery.as_ref(),
            Socket::Game => self.game.as_ref(),
        }
    }

    fn recv_one(&mut self, which: Socket) -> Result<Option<Datagram>, TransportError> {
        let sock = match which {
            Socket::Discovery => self.discovery.as_ref(),
            Socket::Game => self.game.as_ref(),
        };
        let Some(sock) = sock else {
            return Ok(None);
        };
        Ok(
            recv_raw(sock, &mut self.buf)?.map(|(from, bytes)| Datagram {
                socket: which,
                from,
                bytes,
            }),
        )
    }

    /// Read the relay socket until a relayed datagram comes out (events are queued).
    fn recv_relay(&mut self, now: Instant) -> Result<Option<Datagram>, TransportError> {
        let game_port = self.game_port;
        let Some((sock, link)) = self.relay.as_mut() else {
            return Ok(None);
        };
        while let Some((from, bytes)) = recv_raw(sock, &mut self.buf)? {
            match link.handle(now, from, &bytes) {
                Received::Datagram(d) => {
                    let socket = if d.to_port == game_port {
                        Socket::Game
                    } else {
                        Socket::Discovery
                    };
                    return Ok(Some(Datagram {
                        socket,
                        from: d.from,
                        bytes: d.payload,
                    }));
                }
                Received::Event(e) => self.events.push(TransportEvent::Relay(e)),
                Received::NotRelay | Received::Nothing => {}
            }
        }
        Ok(None)
    }
}

impl Transport for UdpTransport {
    fn local_port(&self, socket: Socket) -> Option<u16> {
        self.socket(socket)
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
    }

    fn send(&mut self, socket: Socket, out: &Outgoing) -> Result<(), TransportError> {
        if is_synthetic(out.to) {
            let src_port = match socket {
                Socket::Game => self.game_port,
                Socket::Discovery => self.local_port(Socket::Discovery).unwrap_or(0),
            };
            let Some((sock, link)) = self.relay.as_ref() else {
                return Err(TransportError::NoRelay);
            };
            let wrapped = link.wrap(src_port, out).map_err(TransportError::Relay)?;
            return send_raw(sock, &wrapped);
        }
        let sock = self.socket(socket).ok_or(TransportError::NotOpen(socket))?;
        send_raw(sock, out)
    }

    fn recv(&mut self, now: Instant) -> Result<Option<Datagram>, TransportError> {
        // Rotate which socket is read first so none starves the others.
        self.turn = (self.turn + 1) % 3;
        for k in 0..3 {
            let got = match (self.turn + k) % 3 {
                0 => self.recv_one(Socket::Game)?,
                1 => self.recv_one(Socket::Discovery)?,
                _ => self.recv_relay(now)?,
            };
            if got.is_some() {
                return Ok(got);
            }
        }
        Ok(None)
    }

    fn rebind_game(&mut self) -> Result<(), TransportError> {
        let port = self.game_port;
        // Closed immediately before the bind (2.1).
        drop(self.game.take());
        let mut last = None;
        for attempt in 0..5u64 {
            match bind(self.ip, port) {
                Ok(s) => {
                    self.game = Some(s);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
            std::thread::sleep(Duration::from_millis(5 * (attempt + 1)));
        }
        Err(last.unwrap_or(TransportError::NotOpen(Socket::Game)))
    }

    fn close_discovery(&mut self) {
        self.discovery = None;
    }

    fn poll(&mut self, now: Instant) -> Vec<TransportEvent> {
        if let Some((sock, link)) = self.relay.as_mut() {
            let mut out = Vec::new();
            for e in link.poll(now, &mut out) {
                self.events.push(TransportEvent::Relay(e));
            }
            for o in out {
                if let Err(e) = send_raw(sock, &o) {
                    self.events.push(TransportEvent::Log(format!(
                        "Could not reach the relay at {}: {e}",
                        o.to
                    )));
                }
            }
        }
        std::mem::take(&mut self.events)
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.relay.as_ref().and_then(|(_, l)| l.next_deadline())
    }

    fn open_relay(&mut self, link: RelayLink) -> Result<(), TransportError> {
        let sock = bind(self.ip, 0)?;
        self.relay = Some((sock, link));
        Ok(())
    }

    fn relay_link(&self) -> Option<&RelayLink> {
        self.relay.as_ref().map(|(_, l)| l)
    }

    fn max_datagram_to(&self, to: Endpoint) -> usize {
        match &self.relay {
            Some((_, l)) if is_synthetic(to) => l.max_payload().min(MAX_DATAGRAM),
            _ => MAX_DATAGRAM,
        }
    }

    /// Waits on the game socket (the latency-sensitive one) so a datagram wakes us early.
    fn wait(&mut self, timeout: Duration) {
        let timeout = timeout.max(Duration::from_millis(1));
        let sock = if self.relay.is_some() {
            self.relay.as_ref().map(|(s, _)| s)
        } else {
            self.game.as_ref()
        };
        let Some(sock) = sock else {
            std::thread::sleep(timeout);
            return;
        };
        let blocking =
            sock.set_nonblocking(false).is_ok() && sock.set_read_timeout(Some(timeout)).is_ok();
        if blocking {
            let mut peek = [0u8; 1];
            // Any outcome (data, timeout, a reset, a too-small buffer) ends the wait.
            let _ = sock.peek_from(&mut peek);
        } else {
            std::thread::sleep(timeout);
        }
        let _ = sock.set_nonblocking(true);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sends_receives_and_rebinds() {
        let mut a = UdpTransport::bind(Ipv4Addr::LOCALHOST, Some(0), Some(0)).unwrap();
        let mut b = UdpTransport::bind(Ipv4Addr::LOCALHOST, None, Some(0)).unwrap();
        let a_game = a.local_port(Socket::Game).unwrap();
        let to = SocketAddrV4::new(Ipv4Addr::LOCALHOST, a_game);
        b.send(
            Socket::Game,
            &Outgoing {
                to,
                bytes: vec![1, 2, 3],
            },
        )
        .unwrap();
        let mut got = None;
        for _ in 0..200 {
            if let Some(d) = a.recv(Instant::default()).unwrap() {
                got = Some(d);
                break;
            }
            a.wait(Duration::from_millis(5));
        }
        let d = got.unwrap();
        assert_eq!(d.socket, Socket::Game);
        assert_eq!(d.bytes, vec![1, 2, 3]);
        a.rebind_game().unwrap();
        assert_eq!(a.local_port(Socket::Game), Some(a_game));
        a.close_discovery();
        assert_eq!(a.local_port(Socket::Discovery), None);
        assert!(a
            .send(Socket::Discovery, &Outgoing { to, bytes: vec![] })
            .is_err());
        // A synthetic destination without a relay is refused, not sent.
        let synthetic = crate::relay::peer_endpoint(1, 1337);
        assert!(matches!(
            a.send(
                Socket::Game,
                &Outgoing {
                    to: synthetic,
                    bytes: vec![1]
                }
            ),
            Err(TransportError::NoRelay)
        ));
    }

    #[test]
    fn port_in_use_is_reported() {
        let a = UdpTransport::bind(Ipv4Addr::LOCALHOST, None, Some(0)).unwrap();
        let port = a.local_port(Socket::Game).unwrap();
        let err = UdpTransport::bind(Ipv4Addr::LOCALHOST, None, Some(port)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("UDP port {port} is in use; is another game running?")
        );
    }
}
