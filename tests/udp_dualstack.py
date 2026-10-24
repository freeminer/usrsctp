#!/usr/bin/env python3
"""Keep one SCTP association across IPv6 -> IPv4 -> IPv6 -> IPv4 outages.

The IPv4 relay address is deliberately absent from the server's interfaces,
as with a dual-stack server whose IPv4 address is behind a NAT.
"""
import os
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


def run(binary):
    front6 = udp(socket.AF_INET6, "::1")
    relay_port = front6.getsockname()[1]
    front4 = udp(socket.AF_INET, "127.0.0.2", relay_port)
    back6 = udp(socket.AF_INET6, "::1")
    back4 = udp(socket.AF_INET, "127.0.0.3")
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
        auth_probes = 0
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
                    back6.sendto(data, ("::1", server_port))
                elif sock is front4 and not active6:
                    kinds = list(chunks(data))
                    if 193 in kinds:
                        assert 15 in kinds, "ASCONF probe must be authenticated"
                        auth_probes += 1
                    assert confirmed4 or not any(kind in (0, 64) for kind in kinds),                         "DATA sent before IPv4 path verification"
                    back4.sendto(data, ("127.0.0.1", server_port))
                elif sock is back6 and active6:
                    front6.sendto(data, ("::1", client_port))
                elif sock is back4 and not active6:
                    if 5 in chunks(data):
                        confirmed4 = True
                    front4.sendto(data, ("127.0.0.1", client_port))
            if last_rx > switch_rx + 50:
                print(f"PASS: phase {phase} IPv{6 if active6 else 4}, echo {last_rx}",
                      flush=True)
                switch_rx = last_rx
                phase += 1
                deadline = time.monotonic() + 12
        assert phase == 4, f"family handoff {phase} failed; last echo {last_rx}"
        assert auth_probes > 0, "IPv4 ASCONF probing was not exercised"
        assert confirmed4, "IPv4 path was never verified"
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
    subprocess.run(
        ["cc", *shlex.split(os.getenv("CFLAGS", "")), "-std=c11",
         "-D_DEFAULT_SOURCE", "-pthread", "-I" + str(ROOT / "usrsctplib"),
         str(ROOT / "tests/udp_rebind_peer.c"), sys.argv[1], "-o", str(binary)],
        check=True)
    run(binary)
