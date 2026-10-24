# UDP rebinding regression

Build a static usrsctp library, then run:

```sh
python3 tests/udp_rebind.py build/usrsctplib/libusrsctp.a
SCTP_TEST_IPV6=1 python3 tests/udp_rebind.py build/usrsctplib/libusrsctp.a
```

The test uses independent client/server stacks and a loopback UDP relay. It
changes the relay's source IP and port, returns to a previously known address,
then changes only the port. Each phase requires bidirectional application data
on the original sockets. No reconnect, network namespace, or external server is
used. IPv6 tests port changes on ::1; global IPv6 address changes and Android
network routing still require integration testing.

During the first IPv4 handoff, the relay corrupts AUTH HMACs while recomputing
valid CRC32c checksums. The server must not reply to that new source until valid
authenticated ASCONF packets are allowed through. This also exercises ASCONF
retransmission on the same path.

For memory-safety checks, build the library with
`-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"`, then set
`CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"` when running the
test. Set `ASAN_OPTIONS=detect_leaks=0`: endpoints are deliberately terminated
after the data assertions, without testing graceful stack teardown.
`SCTP_TEST_TRACE=1` prints packet chunk types and endpoint diagnostics.

## IPv6/IPv4 handoff

```sh
python3 tests/udp_dualstack.py build/usrsctplib/libusrsctp.a
```

This uses dual-stack sockets and connectx candidates, then drops all relay
traffic for one address family at a time. It requires application echoes over
IPv6, IPv4, IPv6, and IPv4 on the original association. The relay's IPv4 address
is not a server interface address, reproducing a public NAT endpoint missing
from INIT-ACK. IPv4 probing must contain AUTH and ASCONF; DATA must wait for
HEARTBEAT-ACK path verification. Sanitizer flags above also apply to this test.
