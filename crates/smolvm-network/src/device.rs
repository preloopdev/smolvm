//! smoltcp `phy::Device` adapter for the virtio-net backend.
//!
//! Context
//! =======
//!
//! smoltcp talks to an implementation of its `phy::Device` trait:
//! - `receive()` yields one incoming frame and a transmit token
//! - `transmit()` yields a transmit token when space exists for an outgoing
//!   frame
//! - `capabilities()` describes medium and MTU
//!
//! This module is the narrow adapter layer between:
//! - smoltcp's abstract device API
//! - the queue-based frame transport used by the rest of the virtio runtime
//!
//! Data flow:
//!
//! ```text
//! guest_to_host queue --stage_next_frame--> smoltcp receive()
//! smoltcp transmit() --host_to_guest queue--> frame_stream writer
//! ```
//!
//! More concretely:
//!
//! ```text
//! guest frame arrives in guest_to_host
//!   -> poll loop calls stage_next_frame()
//!   -> poll loop may inspect/classify frame first
//!   -> smoltcp calls receive()
//!   -> DeviceRxToken hands bytes to smoltcp
//!
//! smoltcp wants to emit a frame
//!   -> calls transmit()
//!   -> gets DeviceTxToken
//!   -> fills provided buffer
//!   -> token pushes frame into host_to_guest
//!   -> poll loop later wakes frame writer
//! ```

use crate::queues::NetworkFrameQueues;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// smoltcp `Device` backed by shared frame queues.
///
/// `staged_guest_frame` exists because the poll loop sometimes needs to inspect
/// a frame before handing it to smoltcp. In particular, the stack wants to
/// classify guest TCP SYN and DNS packets before consumption so it can prepare
/// relay/socket state.
///
/// The staging pattern looks like:
///
/// ```text
/// queue -> staged_guest_frame -> RxToken -> smoltcp
/// ```
pub struct VirtioNetworkDevice {
    queues: Arc<NetworkFrameQueues>,
    mtu: usize,
    staged_guest_frame: Option<Vec<u8>>,
    /// Set when smoltcp emitted at least one frame for the guest.
    pub(crate) frames_emitted: AtomicBool,
}

/// RX token representing one guest ethernet frame.
///
/// smoltcp consumes RX tokens immediately; the token just owns the frame bytes
/// until the stack asks to inspect them.
pub struct DeviceRxToken {
    frame: Vec<u8>,
}

/// TX token representing one outgoing frame from smoltcp.
///
/// The token borrows the device so it can enqueue the produced frame when
/// smoltcp finishes writing into the provided buffer.
pub struct DeviceTxToken<'a> {
    device: &'a mut VirtioNetworkDevice,
}

impl VirtioNetworkDevice {
    /// Create a new device for the given queues and MTU.
    ///
    /// `mtu` here is the guest IP MTU, not the full Ethernet frame size.
    /// `capabilities()` translates it to the Ethernet-frame convention expected
    /// by smoltcp.
    pub fn new(queues: Arc<NetworkFrameQueues>, mtu: usize) -> Self {
        Self {
            queues,
            mtu,
            staged_guest_frame: None,
            frames_emitted: AtomicBool::new(false),
        }
    }

    /// Stage one guest frame so the poll loop can inspect it before smoltcp consumes it.
    ///
    /// Why staging exists:
    /// - the frame arrives first in `guest_to_host`
    /// - the poll loop may need to classify it before calling
    ///   `Interface::poll_ingress_single`
    /// - once smoltcp calls `receive()`, ownership moves into an RX token
    ///
    /// So staging gives the poll loop a temporary peek at the next frame
    /// without losing the normal smoltcp `Device` flow.
    ///
    /// This is the key reason the adapter is not just a direct `queue.pop()`
    /// inside `receive()`.
    pub fn stage_next_frame(&mut self) -> Option<&[u8]> {
        if self.staged_guest_frame.is_none() {
            self.staged_guest_frame = self.queues.guest_to_host.pop();
        }

        self.staged_guest_frame.as_deref()
    }

    /// Drop the currently staged guest frame.
    ///
    /// This is used when the poll loop decides not to pass a frame into
    /// smoltcp, for example when the MVP intentionally drops unsupported UDP.
    pub fn drop_staged_frame(&mut self) {
        self.staged_guest_frame = None;
    }
}

impl phy::Device for VirtioNetworkDevice {
    type RxToken<'a> = DeviceRxToken;
    type TxToken<'a> = DeviceTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // smoltcp asks for the next ingress frame only after the poll loop has
        // already staged it. If nothing is staged, there is nothing to receive.
        let frame = self.staged_guest_frame.take()?;
        // This is the single point where a guest-outbound frame is accepted into
        // the stack (frames the poll loop dropped never reach here), so it's the
        // natural place to meter egress. Count the full ethernet frame.
        self.queues.add_egress_bytes(frame.len() as u64);
        Some((DeviceRxToken { frame }, DeviceTxToken { device: self }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // smoltcp may ask for a transmit token even when the downstream writer
        // is temporarily behind. We only hand out a token if the host->guest
        // queue still has room.
        if self.queues.host_to_guest.len() < self.queues.host_to_guest.capacity() {
            Some(DeviceTxToken { device: self })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        // smoltcp wants the maximum Ethernet frame size here, not the Linux IP
        // MTU. For Ethernet devices that means "IP MTU + 14-byte Ethernet
        // header"; see smoltcp's `DeviceCapabilities::max_transmission_unit`
        // documentation.
        capabilities.max_transmission_unit = self.mtu + 14;
        capabilities
    }
}

impl phy::RxToken for DeviceRxToken {
    /// Hand the queued guest frame bytes to smoltcp.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

impl<'a> phy::TxToken for DeviceTxToken<'a> {
    /// Let smoltcp build one Ethernet frame and enqueue it for libkrun.
    ///
    /// Flow:
    ///
    /// ```text
    /// smoltcp fills provided buffer
    ///   -> adapter enqueues frame into host_to_guest
    ///   -> sets frames_emitted
    ///   -> poll loop later wakes the Unix-stream writer
    /// ```
    ///
    /// The queue push is the handoff point. After that, this adapter no longer
    /// owns the frame bytes; the frame writer thread eventually serializes them
    /// onto the libkrun Unix stream.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if self.device.queues.host_to_guest.push(frame).is_ok() {
            self.device.frames_emitted.store(true, Ordering::Relaxed);
        } else {
            tracing::debug!("dropping outbound ethernet frame because the guest queue is full");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queues::DEFAULT_FRAME_QUEUE_CAPACITY;
    use smoltcp::phy::{Device, RxToken};

    #[test]
    fn receive_counts_guest_outbound_bytes_as_egress() {
        let queues = NetworkFrameQueues::shared(DEFAULT_FRAME_QUEUE_CAPACITY);
        let mut dev = VirtioNetworkDevice::new(queues.clone(), 1500);
        assert_eq!(queues.egress_bytes(), 0, "starts at zero");

        // A guest frame must be staged before smoltcp's receive() can take it.
        queues.guest_to_host.push(vec![0u8; 100]).unwrap();
        assert!(dev.stage_next_frame().is_some());
        let (rx, _tx) = dev.receive(Instant::ZERO).expect("frame available");
        rx.consume(|f| assert_eq!(f.len(), 100));
        assert_eq!(queues.egress_bytes(), 100, "one frame metered");

        // A second frame accumulates.
        queues.guest_to_host.push(vec![0u8; 40]).unwrap();
        assert!(dev.stage_next_frame().is_some());
        let (rx, _tx) = dev.receive(Instant::ZERO).expect("frame available");
        rx.consume(|_| {});
        assert_eq!(queues.egress_bytes(), 140, "cumulative");
    }

    #[test]
    fn dropped_staged_frame_is_not_metered() {
        let queues = NetworkFrameQueues::shared(DEFAULT_FRAME_QUEUE_CAPACITY);
        let mut dev = VirtioNetworkDevice::new(queues.clone(), 1500);
        queues.guest_to_host.push(vec![0u8; 100]).unwrap();
        assert!(dev.stage_next_frame().is_some());
        // The poll loop drops frames it won't forward (e.g. unsupported UDP);
        // those never reach the stack, so they must not bill egress.
        dev.drop_staged_frame();
        assert_eq!(queues.egress_bytes(), 0, "dropped frame not metered");
    }
}
