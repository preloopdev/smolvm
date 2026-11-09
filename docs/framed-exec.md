# Framed exec and port connect

Two interfaces for a program that drives a machine, rather than a person at a
terminal: `machine exec --frames` replaces the raw stdin/stdout byte stream
with framed events, and `machine port-connect` relays a host byte stream to a
TCP port on the machine's own loopback.

## Framed exec

```sh
smolvm machine exec --name dev --frames --tty --cols 100 --rows 40 -- /bin/sh -i
```

Each frame is one type byte, a 4-byte big-endian payload length, then the
payload. Neither direction may carry more than 64 KiB in one frame.

| Direction | Type | Payload | Meaning |
|---|---|---|---|
| client → smolvm | `0x01` STDIN | bytes | input for the command |
| client → smolvm | `0x02` RESIZE | `u16` cols, `u16` rows, both big-endian | resize the PTY |
| client → smolvm | `0x03` EOF | empty | close the command's stdin |
| client → smolvm | `0x04` SIGNAL | one byte: 2, 9 or 15 | SIGINT, SIGKILL or SIGTERM |
| smolvm → client | `0x81` OUTPUT | bytes | the command's stdout |
| smolvm → client | `0x82` STDERR | bytes | the command's stderr; never sent with `--tty`, where the PTY merges stderr into stdout |
| smolvm → client | `0x83` EXIT | `i32`, big-endian | always the last frame |
| smolvm → client | `0x84` ERROR | UTF-8 | the command did not start |

`--cols` and `--rows` need `--frames` and `--tty`; they default to 80×24. The
guest opens every PTY at 80×24, so the initial size is sent as the first
`RESIZE` once the command has started: a program that asks for its size after
starting sees the requested one, but the very first output may be laid out for
80×24. Later `RESIZE` frames apply at once. `--timeout` is enforced in the
guest: the command is killed and the `EXIT` frame carries 124. A command killed
by a signal reports 128 + the signal number (SIGKILL is 137), which is the
guest's shell convention.

The client's stream must be well formed. A frame larger than 64 KiB,
an unknown type, a payload of the wrong length, or an unsupported signal number
ends the session and the command, and `smolvm` exits 2 with the reason on
stderr. If a write of `OUTPUT`/`STDERR` frames fails because the client is gone,
`smolvm` waits one second and then exits, closing the agent connection so the
guest kills the command.

**Signals are limited by the agent protocol.** A PTY session can carry SIGINT:
the frame is written as the terminal's interrupt character and the line
discipline delivers it to the foreground process group. There is no request in
the agent protocol to signal a command, so SIGTERM and SIGKILL — and SIGINT on
a pipe session, which has no line discipline — end the session instead. The
guest then kills the command tree with SIGKILL, and the `EXIT` frame carries
137. Use the framed stream for a command that exits on its own or on SIGINT;
tear down anything else by closing the stream.

## Port connect

```sh
smolvm machine port-connect --name dev --port 8080 < request.bin > response.bin
```

The machine must be running. `port-connect` writes `8080\n` on the
port-forward channel first, then relays its stdin to the machine's
`127.0.0.1:8080` and that connection's bytes to its stdout, unchanged, until
either side closes. Standard input reaching EOF closes the guest connection's
write half, so a request/response exchange finishes without the client closing
the whole stream. A clean close in either direction exits 0 and prints nothing
to stdout. A workload container has no network namespace of its own, so a port
a workload inside an image machine listens on at `127.0.0.1` is the port this
reaches.

Every machine this version starts enables the channel, with or without `--net`;
the per-VM socket path is short by construction, and a host whose socket path
limit refuses it logs a warning and loses only live port changes. A machine
started by an older `smolvm` has no `port-forward.sock`; the command fails and
names the socket it tried. If the machine runs an agent rootfs from before the
guest forwarder existed, the socket exists but each connection closes at once.

When nothing is listening on the guest port, the guest forwarder drops the
connection. `port-connect` sees EOF and prints one line to stderr saying the
machine closed the connection without sending any data. It still exits 0,
because a server that accepts and closes without writing a byte looks
identical: neither case can be told apart from the host. Check the guest's exit
status or its own logs when a tunnel that should answer closes instantly.
