//! Name lookups off the caller's thread (SPEC 2.3 and 2.10: names are resolved
//! asynchronously). Each [`Lookup`] runs on one short-lived thread and hands its answer
//! back through a channel, which [`Lookup::poll`] reads without blocking. IPv4 only.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::types::Endpoint;

/// The first IPv4 address of `host` at `port`, resolving on the calling thread.
pub fn resolve_v4(host: &str, port: u16) -> Option<Endpoint> {
    (host, port).to_socket_addrs().ok()?.find_map(|a| match a {
        SocketAddr::V4(v) => Some(v),
        SocketAddr::V6(_) => None,
    })
}

/// One lookup of one or more `(name, port)` pairs, running on its own thread.
#[derive(Debug)]
pub struct Lookup {
    rx: Option<Receiver<Vec<Option<Endpoint>>>>,
}

impl Lookup {
    /// Start resolving every pair. Fails only if the thread cannot be started.
    pub fn spawn(names: Vec<(String, u16)>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("btm-netplay-lookup".to_owned())
            .spawn(move || {
                let found = names.iter().map(|(h, p)| resolve_v4(h, *p)).collect();
                // The node may be gone by now; then nobody wants the answer.
                let _ = tx.send(found);
            })?;
        Ok(Self { rx: Some(rx) })
    }

    /// The answer, once it is there (afterwards `None` again): per pair, in order, its
    /// IPv4 endpoint or `None`. A lookup thread that died answers with nothing found.
    pub fn poll(&mut self) -> Option<Vec<Option<Endpoint>>> {
        let rx = self.rx.as_ref()?;
        let found = match rx.try_recv() {
            Ok(v) => v,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Vec::new(),
        };
        self.rx = None;
        Some(found)
    }

    /// Still waiting for the answer.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[test]
    fn resolves_on_another_thread_and_answers_once() {
        let mut l = Lookup::spawn(vec![("127.0.0.1".to_owned(), 1338)]).unwrap();
        let t0 = Instant::now();
        let found = loop {
            if let Some(f) = l.poll() {
                break f;
            }
            assert!(t0.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(found, vec![Some(Endpoint::new(Ipv4Addr::LOCALHOST, 1338))]);
        assert!(!l.is_pending());
        assert_eq!(l.poll(), None);
    }
}
