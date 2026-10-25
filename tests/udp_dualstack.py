#!/usr/bin/env python3
"""Keep one SCTP association across IPv6 -> IPv4 -> IPv6 -> IPv4 outages.

The IPv4 relay address is deliberately absent from the server's interfaces,
as with a dual-stack server whose IPv4 address is behind a NAT.
"""
import os
import ipaddress
import pathlib
import select
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRIVATE = bool(os.getenv("SCTP_TEST_PRIVATE"))
LOST_ACK = bool(os.getenv("SCTP_TEST_LOST_ACK"))
IPV4 = "127.0.0.2"
TARGET4 = "127.0.0.1"
if PRIVATE:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))  # Route query only; no packet is sent.
        IPV4 = TARGET4 = route.getsockname()[0]
    assert any(ipaddress.ip_address(IPV4) in ipaddress.ip_network(network)
               for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), (
                   "private-source test needs a local RFC1918 IPv4 address")
    os.environ["SCTP_TEST_IPV4"] = IPV4


def udp(family, address, port=0):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    return sock



def chunks(data):
    offset = 12
    while offset + 4 <= len(data):
        kind, _, length = struct.unpack_from("!BBH", data, offset)
        if length < 4 or offset + length > len(data):
            break
        yield kind
        offset += (length + 3) & ~3



def asconf_serials(data):
    offset = 12
    while offset + 8 <= len(data):
        kind, _, length = struct.unpack_from("!BBH", data, offset)
        if length < 4 or offset + length > len(data):
            break
        if kind == 193 and length >= 8:
            yield struct.unpack_from("!I", data, offset + 4)[0]
        offset += (length + 3) & ~3


def run(binary):
    front6 = udp(socket.AF_INET6, "::1")
    relay_port = front6.getsockname()[1]
    front4 = udp(socket.AF_INET, IPV4, relay_port)
    back6 = udp(socket.AF_INET6, "::1")
    back4 = udp(socket.AF_INET, TARGET4 if PRIVATE else "127.0.0.3")
    reserved = [udp(socket.AF_INET, "127.0.0.1") for _ in range(2)]
    client_port, server_port = [sock.getsockname()[1] for sock in reserved]
    for sock in reserved:
        sock.close()
    processes, logs = [], []
    successful = False
    try:
        for role, port in (("server", server_port), ("client", client_port)):
            log = tempfile.TemporaryFile(mode="w+")
            logs.append(log)
            process = subprocess.Popen(
                [str(binary), role, str(port), str(relay_port), "dual"],
                stdout=subprocess.PIPE, stderr=log, bufsize=0)
            processes.append(process)
            assert process.stdout.readline().strip() == b"READY", role
        client = processes[1]
        phase, last_rx, switch_rx = 0, -1, -1
        pending = b""
        confirmed4 = False
        source_acked4 = False
        auth_probes = 0
        lost_ack = False
        serials6 = set()
        fresh4 = False
        deadline = time.monotonic() + 12
        while phase < 4 and time.monotonic() < deadline:
            active6 = phase % 2 == 0
            ready, _, _ = select.select(
                [front6, front4, back6, back4, client.stdout], [], [], .05)
            for sock in ready:
                if sock is client.stdout:
                    data = sock.read(4096)
                    assert data, f"client exited: {client.poll()}"
                    pending += data
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        assert line != b"CLOSED", "association closed"
                        if line.startswith(b"RX "):
                            last_rx = int(line[3:])
                    continue
                data, _ = sock.recvfrom(65535)
                if sock is front6 and active6:
                    serials6.update(asconf_serials(data))
                    back6.sendto(data, ("::1", server_port))
                elif sock is front4 and not active6:
                    kinds = list(chunks(data))
                    if any(serial not in serials6 for serial in asconf_serials(data)):
                        fresh4 = True
                    if 193 in kinds:
                        assert 15 in kinds, "ASCONF probe must be authenticated"
                        auth_probes += 1
                    permitted = source_acked4 if PRIVATE else confirmed4
                    assert permitted or not any(kind in (0, 64) for kind in kinds), (
                        "DATA sent before IPv4 source/path verification")
                    back4.sendto(data, (TARGET4, server_port))
                elif sock is back6 and active6:
                    if LOST_ACK and phase == 0 and last_rx > 50 and 128 in chunks(data):
                        lost_ack = True
                        continue
                    front6.sendto(data, ("::1", client_port))
                elif sock is back4 and not active6:
                    kinds = list(chunks(data))
                    if LOST_ACK and not PRIVATE and not fresh4:
                        assert all(kind in (15, 128) for kind in kinds), (
                            "duplicate ASCONF must only return a cached ACK, "
                            "not validate a new source or send DATA")
                    if 5 in kinds:
                        confirmed4 = True
                    if 128 in kinds:
                        source_acked4 = True
                    front4.sendto(data, (TARGET4, client_port))
            if last_rx > switch_rx + 50:
                if LOST_ACK and phase == 0 and not lost_ack:
                    continue
                print(f"PASS: phase {phase} IPv{6 if active6 else 4}, echo {last_rx}",
                      flush=True)
                switch_rx = last_rx
                phase += 1
                deadline = time.monotonic() + 12
        assert phase == 4, f"family handoff {phase} failed; last echo {last_rx}"
        assert not LOST_ACK or lost_ack, "lost ASCONF-ACK was not exercised"
        assert fresh4, "a fresh ASCONF must announce the IPv4 source"
        assert auth_probes > 0, "IPv4 ASCONF probing was not exercised"
        assert (source_acked4 if PRIVATE else confirmed4), "IPv4 source/path was never verified"
        print("PASS: authenticated IPv4 probing and path verification before DATA",
              flush=True)
        successful = True
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)
        for role, log in zip(("server", "client"), logs):
            log.seek(0)
            if not successful or os.getenv("SCTP_TEST_TRACE"):
                print(role + ":\n" + log.read(), file=sys.stderr)
            log.close()
        for sock in (front6, front4, back6, back4):
            sock.close()


with tempfile.TemporaryDirectory(prefix="sctp-dualstack-") as temporary:
    binary = pathlib.Path(temporary) / "peer"
    internal_flags, internal_sources = [], []
    if PRIVATE:
        flags_file = pathlib.Path(sys.argv[1]).resolve().parent / "CMakeFiles/usrsctp.dir/flags.make"
        definitions = next(line.partition(" = ")[2] for line in flags_file.read_text().splitlines()
                           if line.startswith("C_DEFINES = "))
        internal_flags = [*shlex.split(definitions), "-DSCTP_TEST_PRIVATE_SOURCE"]
        internal_sources = [str(ROOT / "tests/mobility_source.c")]
    subprocess.run(
        ["cc", *internal_flags, *shlex.split(os.getenv("CFLAGS", "")), "-std=c11",
         "-D_DEFAULT_SOURCE", "-pthread", "-I" + str(ROOT / "usrsctplib"),
         str(ROOT / "tests/udp_rebind_peer.c"), *internal_sources, sys.argv[1], "-o", str(binary)],
        check=True)
    run(binary)
