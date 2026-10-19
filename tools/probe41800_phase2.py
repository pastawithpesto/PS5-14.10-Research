#!/usr/bin/env python3
"""Port 41800 Phase 2: Protocol fingerprinting.

Phase 1 result: HTTP = instant close (<1ms), non-HTTP = held 5s then close.
The server has a protocol parser that rejects HTTP but waits for valid non-HTTP data.

This probe tries: TLS, single-byte fingerprinting, length-prefixed binary,
protobuf-like, mDNS, Spotify binary protocol, and various framing patterns.
"""
import argparse
import socket
import struct
import time
import datetime
import ssl
import os


def make_logger(log_path):
    def log(line=""):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return log


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def banner(log, title):
    log()
    log("=" * 78)
    log(f"== {title}")
    log("=" * 78)


def probe(log, host, port, timeout, inter_sleep, name, request_bytes, use_tls=False):
    banner(log, f"PROBE: {name}  {ts()}")
    log(f"  REQ: {request_bytes[:200]!r}")
    log(f"  ({len(request_bytes)} bytes)")
    if use_tls:
        log("  (TLS wrapper)")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        ct = (time.time() - t0) * 1000
        log(f"  connect: {ct:.1f}ms")

        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s, server_hostname=host)
                log(f"  TLS handshake: OK, version={s.version()}")
            except ssl.SSLError as e:
                elapsed = (time.time() - t0) * 1000
                log(f"  TLS handshake FAILED: {e} ({elapsed:.1f}ms)")
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(inter_sleep)
                return None
            except Exception as e:
                elapsed = (time.time() - t0) * 1000
                log(f"  TLS error: {e} ({elapsed:.1f}ms)")
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(inter_sleep)
                return None

        if request_bytes:
            s.sendall(request_bytes)

        data = b""
        try:
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            log(f"  recv timeout after {len(data)} bytes")

        rt = (time.time() - t0) * 1000
        if data:
            log(f"  RESPONSE: {len(data)} bytes in {rt:.1f}ms")
            log(f"    | hex: {data[:64].hex()}")
            try:
                decoded = data.decode("utf-8", "replace")
                for ln in decoded.splitlines()[:20]:
                    log(f"    | {ln}")
            except Exception:
                log(f"    | (raw) {data[:500]!r}")
        else:
            log(f"  RESPONSE: 0 bytes (closed in {rt:.1f}ms)")
            if rt > 4000:
                log("  ** HELD CONNECTION (protocol wait) **")
            elif rt < 100:
                log("  ** INSTANT CLOSE (rejected format) **")
        s.close()
        return data
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        log(f"  ERROR: {e} ({elapsed:.1f}ms)")
        try:
            s.close()
        except Exception:
            pass
        return None
    finally:
        time.sleep(inter_sleep)


def probe_silent(log, host, port, timeout, inter_sleep, name):
    banner(log, f"PROBE: {name}  {ts()}")
    log("  REQ: (none - silent connect)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        ct = (time.time() - t0) * 1000
        log(f"  connect: {ct:.1f}ms")
        data = b""
        try:
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            log(f"  recv timeout after {len(data)} bytes")
        rt = (time.time() - t0) * 1000
        if data:
            log(f"  SERVER SPEAKS FIRST: {len(data)} bytes in {rt:.1f}ms")
            log(f"    | hex: {data[:64].hex()}")
            try:
                for ln in data.decode("utf-8", "replace").splitlines()[:20]:
                    log(f"    | {ln}")
            except Exception:
                pass
        else:
            log(f"  RESPONSE: 0 bytes (closed in {rt:.1f}ms)")
            if rt > 4000:
                log("  ** SERVER WAITED FOR US TO SPEAK **")
        s.close()
        return data
    except Exception as e:
        log(f"  ERROR: {e}")
        try:
            s.close()
        except Exception:
            pass
        return None
    finally:
        time.sleep(inter_sleep)


def build_probes(host, port):
    return [
        ("silent-connect", None),
        ("tls-handshake", b"", True),
        ("byte-0x16", b"\x16"),
        ("byte-0x17", b"\x17"),
        ("byte-0x47", b"G"),
        ("byte-0x50", b"P"),
        ("byte-0x48", b"H"),
        ("byte-0x43", b"C"),
        ("byte-0x53", b"S"),
        ("byte-0x00", b"\x00"),
        ("byte-0x01", b"\x01"),
        ("byte-0xff", b"\xff"),
        ("len32-be-hello", struct.pack(">I", 5) + b"hello"),
        ("len32-be-getinfo", struct.pack(">I", 7) + b"getInfo"),
        ("len16-be-hello", struct.pack(">H", 5) + b"hello"),
        ("len32-le-hello", struct.pack("<I", 5) + b"hello"),
        ("protobuf-getinfo", b"\x0a\x07getInfo"),
        ("spotify-binary-hello", b"\x00\x00\x00\x0e\x00\x04\x00\x00\x00\x00\x00\x00\x00\x02\x00\x04"),
        ("spotify-ap-hello", b"\x00\x04\x00\x00\x00\x00"),
        ("magic-SPTC", b"SPTC\x00\x00\x00\x01"),
        ("magic-SPOT", b"SPOT\x00\x00\x00\x01"),
        ("magic-ZC", b"ZC\x00\x01\x00\x00\x00\x00"),
        ("mdns-query",
         b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x10_spotify-connect\x04_tcp\x05local\x00"
         b"\x00\xff\x00\x01"),
        ("websocket-upgrade",
         b"GET / HTTP/1.1\r\n"
         b"Host: " + f"{host}:{port}".encode() + b"\r\n"
         b"Upgrade: websocket\r\n"
         b"Connection: Upgrade\r\n"
         b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
         b"Sec-WebSocket-Version: 13\r\n"
         b"\r\n"),
    ]


def main():
    parser = argparse.ArgumentParser(description="Port 41800 Phase 2: Protocol fingerprinting")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    timeout = 6.0
    inter_sleep = 1.5
    log_path = args.log or os.path.join(os.getcwd(), "port41800-phase2.log")
    log = make_logger(log_path)

    probes = build_probes(host, port)

    banner(log, f"PORT 41800 PHASE 2: PROTOCOL FINGERPRINT  {host}:{port}  {ts()}")
    log(f"plan: {len(probes)} probes, {timeout}s timeout, {inter_sleep}s between")

    results = []
    for item in probes:
        if item[1] is None:
            resp = probe_silent(log, host, port, timeout, inter_sleep, item[0])
            results.append((item[0], resp, "silent"))
        elif len(item) > 2 and item[2]:
            resp = probe(log, host, port, timeout, inter_sleep, item[0], item[1], use_tls=True)
            results.append((item[0], resp, "tls"))
        else:
            resp = probe(log, host, port, timeout, inter_sleep, item[0], item[1])
            results.append((item[0], resp, "tcp"))

    banner(log, f"SUMMARY  {ts()}")
    for name, resp, mode in results:
        if resp and len(resp) > 0:
            log(f"  *** {name}: GOT {len(resp)} BYTES ***")
    log(f"\nLog: {log_path}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
