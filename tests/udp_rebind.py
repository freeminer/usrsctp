#!/usr/bin/env python3
"""Run an established SCTP association through repeated UDP/NAT source changes.

Usage: python3 tests/udp_rebind.py path/to/libusrsctp.a
Requires a C compiler and permission to bind loopback UDP sockets. No root,
network namespaces, external server, or changes to host interfaces are needed.
"""
import os
import struct
import shlex
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
IPV6 = bool(os.getenv("SCTP_TEST_IPV6"))
LOOPBACK = "::1" if IPV6 else "127.0.0.1"


def udp(address="127.0.0.1"):
    sock = socket.socket(socket.AF_INET6 if IPV6 else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("::1" if IPV6 else address, 0))
    return sock


def trace(data, direction):
    if not os.getenv("SCTP_TEST_TRACE"):
        return
    chunks, offset = [], 12
    while offset + 4 <= len(data):
        kind, flags, size = struct.unpack_from("!BBH", data, offset)
        if size < 4:
            break
        chunks.append(kind)
        offset += (size + 3) & ~3
    print(direction, chunks, flush=True)



def checksum(data):
    packet = bytearray(data)
    packet[8:12] = bytes(4)
    crc = 0xffffffff
    for value in packet:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def corrupt_auth(data):
    """Damage the HMAC but keep CRC32c valid, so AUTH must reject the packet."""
    offset = 12
    while offset + 4 <= len(data):
        kind, _, size = struct.unpack_from("!BBH", data, offset)
        if size < 4 or offset + size > len(data):
            break
        if kind == 15 and size > 8:
            packet = bytearray(data)
            packet[offset + 8] ^= 1
            assert checksum(data) == struct.unpack_from("<I", data, 8)[0]
            struct.pack_into("<I", packet, 8, checksum(packet))
            return bytes(packet)
        offset += (size + 3) & ~3
    return data


def run(binary):
    front = udp()
    backs = [udp("127.0.0.2"), udp("127.0.0.3"), udp("127.0.0.2"),
             udp("127.0.0.2")]
    reserved = [udp(), udp()]
    client_port, server_port = [s.getsockname()[1] for s in reserved]
    for sock in reserved:
        sock.close()
    processes = []
    logs = []
    successful = False
    try:
        for role, port, remote in (("server", server_port, backs[0].getsockname()[1]),
                                   ("client", client_port, front.getsockname()[1])):
            log = tempfile.TemporaryFile(mode="w+")
            logs.append(log)
            processes.append(subprocess.Popen([str(binary), role, str(port), str(remote), "6" if IPV6 else "4"],
                             stdout=subprocess.PIPE, stderr=log, bufsize=0))
            assert processes[-1].stdout.readline().strip() == b"READY"
        client = processes[1]
        received = b""
        phase, last_rx, switch_rx = 0, -1, -1
        corrupt_until, corrupted = 0, 0
        deadline = time.monotonic() + 8
        while phase < len(backs) and time.monotonic() < deadline:
            readable, _, _ = select.select([front, *backs, client.stdout], [], [], .05)
            for item in readable:
                if item is client.stdout:
                    data = item.read(4096)
                    assert data, f"client exited: {client.poll()}"
                    received += data
                    while b"\n" in received:
                        line, received = received.split(b"\n", 1)
                        assert line != b"CLOSED", "association closed during migration"
                        if line.startswith(b"RX "):
                            last_rx = int(line[3:])
                elif item is front:
                    data, _ = front.recvfrom(65535)
                    trace(data, "client")
                    if not IPV6 and phase == 1 and time.monotonic() < corrupt_until:
                        changed = corrupt_auth(data)
                        if changed != data:
                            corrupted += 1
                        data = changed
                    backs[phase].sendto(data, (LOOPBACK, server_port))
                else:
                    data, _ = item.recvfrom(65535)
                    trace(data, "server")
                    if item is backs[phase]:
                        if not IPV6 and phase == 1 and time.monotonic() < corrupt_until:
                            raise AssertionError("peer accepted an unauthenticated new source")
                        front.sendto(data, (LOOPBACK, client_port))
            if last_rx > switch_rx + 50:
                print(f"PASS: phase {phase}, delivered echo {last_rx}", flush=True)
                phase += 1
                switch_rx = last_rx
                deadline = time.monotonic() + 8
                if phase == 1:
                    corrupt_until = time.monotonic() + 1.5
        assert phase == len(backs), f"traffic did not recover after NAT switch {phase}; last echo {last_rx}"
        assert IPV6 or corrupted > 0, "authentication rejection was not exercised"
        successful = True
        if not IPV6:
            print("PASS: invalid AUTH rejected before source migration", flush=True)
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)
        for role, log in zip(("server", "client"), logs):
            log.seek(0)
            output = log.read()
            if output and (not successful or os.getenv("SCTP_TEST_TRACE")):
                print(role + ":\n" + output, file=sys.stderr)
            log.close()
        for sock in (front, *backs):
            sock.close()


with tempfile.TemporaryDirectory(prefix="sctp-rebind-") as temporary:
    binary = pathlib.Path(temporary) / "peer"
    subprocess.run(["cc", *shlex.split(os.getenv("CFLAGS", "")), "-std=c11", "-D_DEFAULT_SOURCE", "-pthread",
                    "-I" + str(ROOT / "usrsctplib"),
                    str(ROOT / "tests/udp_rebind_peer.c"), sys.argv[1],
                    "-o", str(binary)], check=True)
    run(binary)
