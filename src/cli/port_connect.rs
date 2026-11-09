//! `smolvm machine port-connect`: relay host stdin/stdout to a TCP port
//! listening on the machine's own loopback.
//!
//! A machine's guest loopback is not reachable from the host — TSI and
//! virtio-net both forward only what was published. The port-forward vsock
//! channel is the narrow exception: libkrun bridges a host Unix socket to the
//! guest agent's forwarder, which reads one decimal line naming a guest port
//! and then relays raw bytes to `127.0.0.1:<port>`. That is enough to drive a
//! debug adapter or any other guest-local service from the host without
//! publishing a port on the machine's network interface.
//!
//! The first line on the socket is the port. Everything after it, in both
//! directions, is the caller's byte stream.

use clap::Args;
use smolvm::agent::AgentManager;
use smolvm::network::port_forward::PORT_FORWARD_SOCKET;
use smolvm::platform::uds::UdsStream;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::path::PathBuf;

/// Relay stdin and stdout to a TCP port on a running machine's loopback.
#[derive(Args, Debug)]
pub struct PortConnectCmd {
    /// Target machine (default: "default")
    #[arg(long, value_name = "NAME", env = smolvm::data::consts::ENV_SMOLVM_MACHINE_NAME)]
    pub name: Option<String>,

    /// Guest TCP port to connect to on 127.0.0.1
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
}

impl PortConnectCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let (manager, client) = super::vm_common::ensure_running_and_connect(&self.name)?;
        // This command observes a running machine; it must never stop one.
        manager.detach();
        drop(client);

        let socket = tunnel_socket(&manager)?;
        let mut tunnel = UdsStream::connect(&socket).map_err(|error| {
            smolvm::Error::agent(
                "port connect",
                format!(
                    "cannot open the port-forward socket {}: {error}. \
                     The machine must be running and started by a smolvm that enables \
                     live port forwarding.",
                    socket.display()
                ),
            )
        })?;
        write_target_port(&mut tunnel, self.port).map_err(|error| {
            smolvm::Error::agent(
                "port connect",
                format!("cannot name the guest port: {error}"),
            )
        })?;

        let mut stdout = io::stdout().lock();
        let received = relay(tunnel, io::stdin(), &mut stdout).map_err(|error| {
            smolvm::Error::agent("port connect", format!("relay failed: {error}"))
        })?;
        if received == 0 {
            // The guest forwarder drops the connection when nothing listens on
            // the port. A server that accepts and closes without writing looks
            // the same, so this is a note, not a verdict.
            eprintln!(
                "smolvm: the machine closed the connection without sending any data; \
                 nothing may be listening on 127.0.0.1:{}",
                self.port
            );
        }
        Ok(())
    }
}

/// The host end of the machine's port-forward bridge.
fn tunnel_socket(manager: &AgentManager) -> smolvm::Result<PathBuf> {
    manager
        .vsock_socket()
        .parent()
        .map(|dir| dir.join(PORT_FORWARD_SOCKET))
        .ok_or_else(|| {
            smolvm::Error::agent(
                "port connect",
                "the machine's agent socket has no parent directory",
            )
        })
}

/// Name the guest port on the tunnel. The guest reads this one line before it
/// starts relaying, so nothing else may be written first.
fn write_target_port(writer: &mut impl Write, port: u16) -> io::Result<()> {
    writer.write_all(format!("{port}\n").as_bytes())?;
    writer.flush()
}

/// Relay `input` to the tunnel and the tunnel to `output` until either side
/// closes. Returns how many bytes the guest sent.
///
/// stdin EOF closes the tunnel's write half so the guest sees EOF; the guest
/// closing ends the read loop, which leaves the stdin thread blocked (a read
/// from stdin cannot be interrupted) and lets the process exit.
fn relay(
    mut tunnel: UdsStream,
    mut input: impl Read + Send + 'static,
    output: &mut impl Write,
) -> io::Result<u64> {
    let mut writer = tunnel.try_clone()?;
    let uplink = std::thread::Builder::new()
        .name("port-connect-stdin".into())
        .spawn(move || -> io::Result<()> {
            let mut buffer = [0u8; 64 * 1024];
            loop {
                match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => writer.write_all(&buffer[..n])?,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            writer.shutdown(Shutdown::Write)
        })?;

    let mut received = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match tunnel.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                output.write_all(&buffer[..n])?;
                output.flush()?;
                received += n as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // The guest forwarder refuses a port by dropping the connection.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    // The tunnel is finished; a stdin thread still parked in a read is left
    // behind so this command can return without waiting for the caller to
    // close stdin.
    drop(uplink);
    Ok(received)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;

    #[test]
    fn the_guest_port_is_the_first_line_and_nothing_else() {
        let mut out = Vec::new();
        write_target_port(&mut out, 8080).unwrap();
        assert_eq!(out, b"8080\n");

        out.clear();
        write_target_port(&mut out, 1).unwrap();
        assert_eq!(out, b"1\n");
    }

    #[test]
    fn the_relay_carries_both_directions_until_each_side_closes() {
        let (mut host_tunnel, mut guest_tunnel) = UdsStream::pair().unwrap();
        let (input_read, mut input_write) = UdsStream::pair().unwrap();
        let (mut output_read, mut output_write) = UdsStream::pair().unwrap();

        write_target_port(&mut host_tunnel, 8080).unwrap();
        let relay_thread =
            std::thread::spawn(move || relay(host_tunnel, input_read, &mut output_write));

        // The guest reads its port header before any relayed byte.
        let mut header = [0u8; 5];
        guest_tunnel.read_exact(&mut header).unwrap();
        assert_eq!(&header, b"8080\n");

        // Host stdin reaches the guest, and its EOF closes that half.
        input_write.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        input_write.shutdown(Shutdown::Write).unwrap();
        let mut request = Vec::new();
        guest_tunnel.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"GET / HTTP/1.0\r\n\r\n");

        // Guest output reaches host stdout.
        guest_tunnel.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        guest_tunnel.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        output_read.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"HTTP/1.0 200 OK\r\n\r\n");

        assert_eq!(relay_thread.join().unwrap().unwrap(), 19);
        // The guest-side stream is closed; nothing else was written to it.
        let mut extra = Vec::new();
        assert_eq!(guest_tunnel.read(&mut extra).unwrap(), 0);
    }

    #[test]
    fn a_guest_that_closes_first_ends_the_relay_with_no_bytes() {
        let (host_tunnel, guest_tunnel) = UdsStream::pair().unwrap();
        let (input_read, _input_write) = UdsStream::pair().unwrap();
        let mut output = Vec::new();
        guest_tunnel.shutdown(Shutdown::Both).unwrap();
        let received = relay(host_tunnel, input_read, &mut output).unwrap();
        assert_eq!(received, 0);
        assert!(output.is_empty());
    }
}
