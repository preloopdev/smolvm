//! Framed I/O for `smolvm machine exec --frames`.
//!
//! A driver that owns the process's stdin and stdout (a sandbox host agent, a
//! protocol relay) cannot use a terminal's raw byte stream: it has to tell
//! stdin data apart from a resize, and the command's output apart from its exit
//! status. `--frames` replaces the raw stream with a small binary facility:
//!
//! ```text
//! client -> smolvm           smolvm -> client
//!   0x01 STDIN   (bytes)       0x81 OUTPUT (bytes)
//!   0x02 RESIZE  (cols,rows)   0x82 STDERR (bytes, never with --tty)
//!   0x03 EOF     (empty)       0x83 EXIT   (i32, always last)
//!   0x04 SIGNAL  (number)      0x84 ERROR  (UTF-8; the command did not start)
//! ```
//!
//! Every frame is one type byte, a 4-byte big-endian payload length, then the
//! payload; a payload is at most [`MAX_PAYLOAD`] bytes. The transport itself is
//! the agent's existing interactive session ([`crate::agent::AgentClient::vm_exec_interactive_io`]),
//! fed through [`InteractiveInput`] — no guest code is involved.

use crate::agent::{
    interactive_input, InteractiveInput, InteractiveInputReceiver, InteractiveInputSender,
    InteractiveOutput,
};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Largest payload either side may put in one frame.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// One byte of frame type, four of big-endian payload length.
const HEADER_LEN: usize = 5;

// Client -> smolvm.
const TYPE_STDIN: u8 = 0x01;
const TYPE_RESIZE: u8 = 0x02;
const TYPE_EOF: u8 = 0x03;
const TYPE_SIGNAL: u8 = 0x04;

// smolvm -> client.
const TYPE_OUTPUT: u8 = 0x81;
const TYPE_STDERR: u8 = 0x82;
const TYPE_EXIT: u8 = 0x83;
const TYPE_ERROR: u8 = 0x84;

const SIGINT: u8 = 2;
const SIGTERM: u8 = 15;
const SIGKILL: u8 = 9;

/// The terminal's interrupt character. On a PTY the line discipline turns it
/// into SIGINT for the foreground process group, which is the one signal the
/// existing interactive path can deliver without new guest code.
const ETX: u8 = 0x03;

/// Session-ended exit status reported when the guest agent kills the command
/// because the host connection closed: 128 + SIGKILL.
const KILLED_EXIT_CODE: i32 = 128 + SIGKILL as i32;

/// Input events that may wait for the session to take them. Reading stops
/// while the queue is full, which is how a fast client is held back.
const INPUT_QUEUE_EVENTS: usize = 16;

/// How long a failed stdout write waits before the process ends and the agent
/// kills the command. Gives the client a moment to recover a wedged reader.
const WRITE_FAILURE_GRACE: Duration = Duration::from_secs(1);

/// The PTY size and terminal mode a framed session starts with.
#[derive(Debug, Clone, Copy)]
pub struct SessionOptions {
    /// Run the command on a PTY (`--tty`).
    pub tty: bool,
    /// Initial PTY width, used only with `tty`.
    pub cols: u16,
    /// Initial PTY height, used only with `tty`.
    pub rows: u16,
}

/// A frame read from the client's stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InputFrame {
    Stdin(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Eof,
    Signal(u8),
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

/// Read one client frame, or `None` when stdin ended exactly at a frame
/// boundary. Every read is a `read` loop, so a frame split across several
/// delivery boundaries is reassembled before it is interpreted.
fn read_frame(reader: &mut impl Read) -> io::Result<Option<InputFrame>> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(invalid("stdin ended in the middle of a frame header")),
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }

    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(invalid(format!(
            "frame type {kind:#04x} carries {len} bytes, over the {MAX_PAYLOAD}-byte limit"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid(format!(
                "stdin ended in the middle of a frame payload (type {kind:#04x}, {len} bytes)"
            ))
        } else {
            error
        }
    })?;

    match kind {
        TYPE_STDIN => Ok(Some(InputFrame::Stdin(payload))),
        TYPE_RESIZE if len == 4 => Ok(Some(InputFrame::Resize {
            cols: u16::from_be_bytes([payload[0], payload[1]]),
            rows: u16::from_be_bytes([payload[2], payload[3]]),
        })),
        TYPE_RESIZE => Err(invalid(format!(
            "resize frame carries {len} bytes, expected 4"
        ))),
        TYPE_EOF if len == 0 => Ok(Some(InputFrame::Eof)),
        TYPE_EOF => Err(invalid(format!(
            "eof frame carries {len} bytes, expected none"
        ))),
        TYPE_SIGNAL if len == 1 && matches!(payload[0], SIGINT | SIGTERM | SIGKILL) => {
            Ok(Some(InputFrame::Signal(payload[0])))
        }
        TYPE_SIGNAL if len != 1 => Err(invalid(format!(
            "signal frame carries {len} bytes, expected 1"
        ))),
        TYPE_SIGNAL => Err(invalid(format!(
            "signal frame names {} — only SIGINT (2), SIGKILL (9) and SIGTERM (15) are accepted",
            payload[0]
        ))),
        other => Err(invalid(format!("unknown frame type {other:#04x}"))),
    }
}

/// Write one frame. Payloads above [`MAX_PAYLOAD`] are refused rather than
/// truncated; callers split output first.
fn write_frame(writer: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "frame payload {} exceeds the {MAX_PAYLOAD}-byte limit",
                payload.len()
            ),
        ));
    }
    let mut header = [0u8; HEADER_LEN];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Write `data` as one or more `kind` frames. An empty chunk writes nothing.
fn write_chunked(writer: &mut impl Write, kind: u8, data: &[u8]) -> io::Result<()> {
    debug_assert!(matches!(kind, TYPE_OUTPUT | TYPE_STDERR));
    for chunk in data.chunks(MAX_PAYLOAD) {
        write_frame(writer, kind, chunk)?;
    }
    Ok(())
}

/// What a framed session ended with, before it is turned into a process exit.
enum Outcome {
    /// The command ran; carry its exit status.
    Exit(i32),
    /// The client's stream violated the frame format.
    ProtocolError(String),
}

/// Shared state between the stdin reader and the session.
#[derive(Default)]
struct Control {
    /// The first frame-format error, if the client's stream had one.
    input_error: Mutex<Option<String>>,
    /// A signal that ended the session instead of being delivered.
    aborted: AtomicBool,
}

impl Control {
    fn record_error(&self, message: String) {
        let mut slot = self.input_error.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(message);
        }
    }

    fn take_error(&self) -> Option<String> {
        self.input_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }
}

/// Read client frames from stdin and feed them to the session.
///
/// Runs on its own thread because stdin blocks. Dropping the sender is what
/// tells the session the client is gone; a clean EOF does not drop it, because
/// the client has only stopped producing input and still wants the command's
/// output and exit status.
fn spawn_reader(
    sender: InteractiveInputSender,
    control: Arc<Control>,
    options: SessionOptions,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("exec-frames-stdin".into())
        .spawn(move || {
            if options.tty
                && sender
                    .send_blocking(InteractiveInput::Resize {
                        cols: options.cols,
                        rows: options.rows,
                    })
                    .is_err()
            {
                return;
            }
            let mut stdin = io::stdin().lock();
            loop {
                match read_frame(&mut stdin) {
                    Ok(Some(InputFrame::Stdin(data))) => {
                        if sender.send_blocking(InteractiveInput::Stdin(data)).is_err() {
                            return;
                        }
                    }
                    Ok(Some(InputFrame::Resize { cols, rows })) => {
                        // A resize on a pipe session has no terminal to change.
                        if options.tty
                            && sender
                                .send_blocking(InteractiveInput::Resize { cols, rows })
                                .is_err()
                        {
                            return;
                        }
                    }
                    Ok(Some(InputFrame::Eof)) => {
                        // No more input, but the client is still there: close
                        // the command's stdin and keep reading, so a later
                        // SIGNAL frame can still end the session.
                        let _ = sender.send_blocking(InteractiveInput::Eof);
                    }
                    Ok(None) => {
                        // The client closed its stdin instead of sending EOF.
                        // Nothing more can arrive, but the client is still
                        // reading, so the command must run to its exit.
                        let _ = sender.send_blocking(InteractiveInput::Eof);
                        loop {
                            std::thread::park();
                        }
                    }
                    Ok(Some(InputFrame::Signal(SIGINT))) if options.tty => {
                        // The PTY's line discipline delivers SIGINT.
                        if sender
                            .send_blocking(InteractiveInput::Stdin(vec![ETX]))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(Some(InputFrame::Signal(_signal))) => {
                        // The agent protocol has no per-command signal request,
                        // so ending the session is the only lever: dropping the
                        // connection makes the guest kill the command tree.
                        control.aborted.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(error) => {
                        control.record_error(format!("exec --frames: bad frame on stdin: {error}"));
                        return;
                    }
                }
            }
        })
}

/// Run one framed exec session over stdin/stdout and exit the process.
///
/// `start` owns the agent connection and returns the command's exit code; every
/// output chunk it produces is written as a frame. The process exit status is
/// the command's, 2 for a malformed client frame, and 1 for an agent failure.
pub fn run<F>(options: SessionOptions, start: F) -> !
where
    F: FnOnce(InteractiveInputReceiver, &mut dyn FnMut(InteractiveOutput)) -> crate::Result<i32>,
{
    match run_session(options, start) {
        Ok(Outcome::Exit(code)) => std::process::exit(code),
        Ok(Outcome::ProtocolError(message)) => {
            eprintln!("smolvm: {message}");
            std::process::exit(2);
        }
        Err(error) => {
            // The client reads frames, so tell it why the command never ran.
            let message = error.to_string();
            let _ = write_frame(&mut io::stdout(), TYPE_ERROR, message.as_bytes());
            eprintln!("smolvm: {message}");
            std::process::exit(1);
        }
    }
}

fn run_session<F>(options: SessionOptions, start: F) -> crate::Result<Outcome>
where
    F: FnOnce(InteractiveInputReceiver, &mut dyn FnMut(InteractiveOutput)) -> crate::Result<i32>,
{
    let (sender, receiver) = interactive_input(INPUT_QUEUE_EVENTS)
        .map_err(|error| crate::Error::agent("exec --frames", format!("input channel: {error}")))?;
    let control = Arc::new(Control::default());
    let reader = spawn_reader(sender, control.clone(), options)
        .map_err(|error| crate::Error::agent("exec --frames", format!("stdin reader: {error}")))?;

    let mut stdout = io::stdout();
    let mut on_output = |output: InteractiveOutput| {
        let result = match output {
            InteractiveOutput::Stdout(data) => write_chunked(&mut stdout, TYPE_OUTPUT, &data),
            InteractiveOutput::Stderr(data) => write_chunked(&mut stdout, TYPE_STDERR, &data),
        };
        if let Err(error) = result {
            // The client is gone. Ending the process closes the agent
            // connection, which makes the guest kill the command; the grace
            // period comes first so a client that is only briefly stuck is not
            // treated as gone.
            eprintln!("smolvm: cannot write exec frames to stdout: {error}");
            std::thread::sleep(WRITE_FAILURE_GRACE);
            std::process::exit(1);
        }
    };

    let session = start(receiver, &mut on_output);
    drop(reader);

    if let Some(message) = control.take_error() {
        return Ok(Outcome::ProtocolError(message));
    }
    if control.aborted.load(Ordering::SeqCst) {
        // The session ended by dropping the agent connection, which is how the
        // guest was told to kill the command tree; report the kill it caused.
        write_frame(&mut stdout, TYPE_EXIT, &KILLED_EXIT_CODE.to_be_bytes()).map_err(|error| {
            crate::Error::agent("exec --frames", format!("exit frame: {error}"))
        })?;
        return Ok(Outcome::Exit(KILLED_EXIT_CODE));
    }
    let code = session?;
    write_frame(&mut stdout, TYPE_EXIT, &code.to_be_bytes())
        .map_err(|error| crate::Error::agent("exec --frames", format!("exit frame: {error}")))?;
    Ok(Outcome::Exit(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Delivers at most one byte per `read`, the way a socket may.
    struct Trickle<'a> {
        bytes: &'a [u8],
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.bytes.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.bytes[0];
            self.bytes = &self.bytes[1..];
            Ok(1)
        }
    }

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn parse(bytes: &[u8]) -> io::Result<Option<InputFrame>> {
        read_frame(&mut Trickle { bytes })
    }

    /// Decode server frames the way the client does, without the client-only
    /// type validation `read_frame` applies.
    fn parse_server(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut reader = Trickle { bytes };
        let mut frames = Vec::new();
        loop {
            let mut header = [0u8; HEADER_LEN];
            if reader.read(&mut header[..1]).unwrap() == 0 {
                return frames;
            }
            reader.read_exact(&mut header[1..]).unwrap();
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).unwrap();
            frames.push((header[0], payload));
        }
    }

    #[test]
    fn client_frames_are_read_whole_however_the_bytes_arrive() {
        assert_eq!(
            parse(&frame(TYPE_STDIN, b"echo ok\n")).unwrap(),
            Some(InputFrame::Stdin(b"echo ok\n".to_vec()))
        );
        assert_eq!(
            parse(&frame(TYPE_RESIZE, &[0, 100, 0, 40])).unwrap(),
            Some(InputFrame::Resize {
                cols: 100,
                rows: 40
            })
        );
        assert_eq!(parse(&frame(TYPE_EOF, b"")).unwrap(), Some(InputFrame::Eof));
        assert_eq!(
            parse(&frame(TYPE_SIGNAL, &[SIGKILL])).unwrap(),
            Some(InputFrame::Signal(SIGKILL))
        );
    }

    #[test]
    fn a_clean_end_between_frames_is_not_an_error() {
        assert_eq!(parse(b"").unwrap(), None);
        let two = [frame(TYPE_STDIN, b"a"), frame(TYPE_STDIN, b"bc")].concat();
        let mut reader = Trickle { bytes: &two };
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            Some(InputFrame::Stdin(b"a".to_vec()))
        );
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            Some(InputFrame::Stdin(b"bc".to_vec()))
        );
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn oversize_and_malformed_frames_are_rejected_before_use() {
        let oversized = frame(TYPE_STDIN, &[]);
        let mut bytes = oversized.clone();
        bytes[1..5].copy_from_slice(&((MAX_PAYLOAD + 1) as u32).to_be_bytes());
        let error = parse(&bytes).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("over the"), "{error}");

        // An absurd length is refused without trying to allocate it.
        let mut bytes = oversized;
        bytes[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse(&bytes).is_err());

        assert!(parse(&frame(0x42, b"")).is_err(), "unknown type");
        assert!(
            parse(&frame(TYPE_RESIZE, &[0, 80, 0])).is_err(),
            "short resize"
        );
        assert!(parse(&frame(TYPE_EOF, b"x")).is_err(), "eof with payload");
        assert!(
            parse(&frame(TYPE_SIGNAL, &[SIGHUP])).is_err(),
            "unsupported signal"
        );
        assert!(
            parse(&frame(TYPE_SIGNAL, &[])).is_err(),
            "signal without a number"
        );
    }

    #[test]
    fn a_frame_cut_short_is_an_error_not_a_silent_end() {
        let whole = frame(TYPE_STDIN, b"payload");
        let error = parse(&whole[..whole.len() - 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("middle of a frame payload"));
        let error = parse(&whole[..3]).unwrap_err();
        assert!(error.to_string().contains("middle of a frame header"));
    }

    #[test]
    fn server_frames_carry_the_documented_layout() {
        let mut out = Vec::new();
        write_frame(&mut out, TYPE_OUTPUT, b"ok\n").unwrap();
        assert_eq!(out, b"\x81\x00\x00\x00\x03ok\n");

        out.clear();
        write_frame(&mut out, TYPE_STDERR, b"e").unwrap();
        assert_eq!(out, b"\x82\x00\x00\x00\x01e");

        out.clear();
        write_frame(&mut out, TYPE_EXIT, &(-1i32).to_be_bytes()).unwrap();
        assert_eq!(out, b"\x83\x00\x00\x00\x04\xff\xff\xff\xff");

        out.clear();
        write_frame(&mut out, TYPE_ERROR, b"no").unwrap();
        assert_eq!(out, b"\x84\x00\x00\x00\x02no");
    }

    #[test]
    fn output_is_split_into_payloads_within_the_limit() {
        let mut out = Vec::new();
        let data = vec![b'z'; MAX_PAYLOAD + 3];
        write_chunked(&mut out, TYPE_OUTPUT, &data).unwrap();

        let frames = parse_server(&out);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0],
            (TYPE_OUTPUT, vec![b'z'; MAX_PAYLOAD]),
            "one frame per 64 KiB of output"
        );
        assert_eq!(frames[1], (TYPE_OUTPUT, vec![b'z'; 3]));
    }

    #[test]
    fn an_oversize_server_payload_is_refused_rather_than_truncated() {
        let mut out = Vec::new();
        let error = write_frame(&mut out, TYPE_OUTPUT, &vec![b'x'; MAX_PAYLOAD + 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(out.is_empty());
    }

    const SIGHUP: u8 = 1;
}
