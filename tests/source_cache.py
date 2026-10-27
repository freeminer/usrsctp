#!/usr/bin/env python3
"""Recover DATA after a stale source is pinned while AUTH/ASCONF remains live.

Requires a native CMake usrsctp build and a non-loopback local IPv4 address.
No interface or route configuration is changed.
"""
import os
import json
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
library = pathlib.Path(sys.argv[1]).resolve()


def udp(address="127.0.0.1"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 0))
    return sock


def kinds(data):
    offset = 12
    while offset + 4 <= len(data):
        kind, _, length = struct.unpack_from("!BBH", data, offset)
        if length < 4 or offset + length > len(data):
            return
        yield kind
        offset += (length + 3) & ~3



def valid_checksum(data):
    packet = bytearray(data)
    expected = struct.unpack_from("<I", packet, 8)[0]
    packet[8:12] = bytes(4)
    crc = 0xffffffff
    for value in packet:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (crc ^ 0xffffffff) == expected


with tempfile.TemporaryDirectory(prefix="sctp-source-cache-") as temporary:
    binary = pathlib.Path(temporary) / "peer"
    flags_file = library.parent / "CMakeFiles/usrsctp.dir/flags.make"
    if flags_file.exists():
        definitions = shlex.split(next(line.partition(" = ")[2]
                                      for line in flags_file.read_text().splitlines()
                                      if line.startswith("C_DEFINES = ")))
    else:
        commands_file = next(parent / "compile_commands.json"
                             for parent in library.parents
                             if (parent / "compile_commands.json").exists())
        command = next(entry["command"] for entry in json.loads(commands_file.read_text())
                       if entry["file"].endswith("usrsctplib/user_socket.c"))
        definitions = [flag for flag in shlex.split(command) if flag.startswith("-D")]
    subprocess.run(
        ["cc", *definitions, *shlex.split(os.getenv("CFLAGS", "")),
         "-DSCTP_TEST_SOURCE_CACHE", "-std=c11", "-pthread",
         "-I" + str(ROOT / "usrsctplib"), str(ROOT / "tests/udp_rebind_peer.c"),
         str(ROOT / "tests/mobility_source.c"), str(library), "-o", str(binary)],
        check=True)
    front, back = udp("127.0.0.2"), udp("127.0.0.3")
    reserved = [udp(), udp()]
    client_port, server_port = [sock.getsockname()[1] for sock in reserved]
    for sock in reserved:
        sock.close()
    processes, logs = [], []
    passed = False
    try:
        for role, port, remote in (("server", server_port, back.getsockname()[1]),
                                   ("client", client_port, front.getsockname()[1])):
            log = tempfile.TemporaryFile(mode="w+")
            logs.append(log)
            process = subprocess.Popen(
                [str(binary), role, str(port), str(remote), "dual4"],
                stdout=subprocess.PIPE, stderr=log, bufsize=0)
            processes.append(process)
            assert process.stdout.readline().strip() == b"READY"
        client = processes[1]
        deadline = time.monotonic() + 5
        pinned = None
        bad_source = ack_after_pin = recovered = inbound_data = False
        buffered = b""
        while time.monotonic() < deadline:
            for sock in select.select([front, back, client.stdout], [], [], .01)[0]:
                if sock is client.stdout:
                    data = sock.read(4096)
                    assert data, f"client exited: {client.poll()}"
                    buffered += data
                    while b"\n" in buffered:
                        line, buffered = buffered.split(b"\n", 1)
                        assert line != b"CLOSED", "association closed"
                        if line == b"PINNED":
                            pinned = time.monotonic()
                            deadline = pinned + 1.2
                        elif line.startswith(b"RX ") and pinned is not None:
                            if line[3:].startswith(b"S"):
                                inbound_data = True
                            elif int(line[3:]) >= 50:
                                recovered = True
                else:
                    data, source = sock.recvfrom(65535)
                    if sock is front:
                        if os.getenv("SCTP_TEST_TRACE"):
                            print("UP", source[0], list(kinds(data)), "crc", valid_checksum(data), flush=True)
                        if source[0] != "127.0.0.1":
                            bad_source = True
                            continue
                        back.sendto(data, ("127.0.0.1", server_port))
                    else:
                        if os.getenv("SCTP_TEST_TRACE"):
                            print("DOWN", list(kinds(data)), flush=True)
                        if pinned is not None and 128 in kinds(data):
                            assert 15 in kinds(data), "source ACK must be authenticated"
                            ack_after_pin = True
                        front.sendto(data, ("127.0.0.1", client_port))
            if bad_source and ack_after_pin and recovered and inbound_data:
                passed = True
                break
        assert bad_source, "the stale source was never used"
        assert ack_after_pin, "inbound authenticated ACK did not reach the client"
        assert inbound_data, "inbound application DATA did not stay live"
        assert recovered, "DATA stayed on the stale source despite authenticated ACKs"
        print("PASS: authenticated source ACK repairs the cached DATA source")
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)
        for role, log in zip(("server", "client"), logs):
            log.seek(0)
            if not passed:
                print(role + ":\n" + log.read(), file=sys.stderr)
            log.close()
        front.close()
        back.close()
