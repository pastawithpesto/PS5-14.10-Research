#!/usr/bin/env python3
"""Port 41800 Phase 3: HTTP variant probing.

Phase 2 found: server IS HTTP internally (returns 500 on binary data).
But well-formed HTTP with Connection:close gets silently dropped.
Hypothesis: Connection:close causes instant close. Try without it,
with keep-alive, with various headers, without Host, etc.
"""
import argparse
import socket
import time
import datetime
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


def probe(log, host, port, timeout, inter_sleep, name, request_bytes):
    banner(log, f"PROBE: {name}  {ts()}")
    log(f"  REQ: {request_bytes[:300]!r}")
    log(f"  ({len(request_bytes)} bytes)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        ct = (time.time() - t0) * 1000
        log(f"  connect: {ct:.1f}ms")
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
                for ln in decoded.splitlines()[:30]:
                    log(f"    | {ln}")
            except Exception:
                log(f"    | (raw) {data[:500]!r}")
        else:
            log(f"  RESPONSE: 0 bytes (closed in {rt:.1f}ms)")
            if rt > 4000:
                log("  ** HELD (waited for data) **")
            elif rt < 100:
                log("  ** INSTANT CLOSE **")
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
    H = host
    P = str(port)
    return [
        ("get-no-conn-close",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() + b"\r\n\r\n"),
        ("get-keep-alive",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nConnection: keep-alive\r\n\r\n"),
        ("get-no-host",
         b"GET /?action=getInfo HTTP/1.1\r\n\r\n"),
        ("get-no-host-10",
         b"GET /?action=getInfo HTTP/1.0\r\n\r\n"),
        ("get-bare-line",
         b"GET /?action=getInfo\r\n\r\n"),
        ("post-json",
         b"POST / HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n"
         b'{"action":"getInfo"}'),
        ("post-json-no-conn",
         b"POST / HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: keep-alive\r\n\r\n"
         b'{"action":"getInfo"}'),
        ("get-spotify-ua",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nUser-Agent: Spotify/8.8.0\r\n\r\n"),
        ("get-origin",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nOrigin: https://open.spotify.com\r\n\r\n"),
        ("get-root-only",
         b"GET / HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() + b"\r\n\r\n"),
        ("get-zeroconf",
         b"GET /ZeroConf?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() + b"\r\n\r\n"),
        ("get-zc-lower",
         b"GET /zc?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() + b"\r\n\r\n"),
        ("get-api",
         b"GET /api?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() + b"\r\n\r\n"),
        ("post-root-form",
         b"POST / HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\n"
         b"action=getInfo\r\n"),
        ("post-zeroconf-form",
         b"POST /ZeroConf HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\n"
         b"action=getInfo\r\n"),
        ("http09", b"GET /?action=getInfo\r\n"),
        ("get-single-crlf",
         b"GET /?action=getInfo HTTP/1.1\r\n"),
        ("get-triple-crlf",
         b"GET /?action=getInfo HTTP/1.1\r\n\r\n\r\n"),
        ("get-cl0",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Length: 0\r\n\r\n"),
        ("get-expect",
         b"GET /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nExpect: 100-continue\r\n\r\n"),
        ("post-empty",
         b"POST /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n"),
        ("post-action-both",
         b"POST /?action=getInfo HTTP/1.1\r\nHost: " + f"{H}:{P}".encode() +
         b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\n"
         b"action=getInfo\r\n"),
    ]


def main():
    parser = argparse.ArgumentParser(description="Port 41800 Phase 3: HTTP variant probing")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    timeout = 6.0
    inter_sleep = 1.5
    log_path = args.log or os.path.join(os.getcwd(), "port41800-phase3.log")
    log = make_logger(log_path)

    probes = build_probes(host, port)

    banner(log, f"PORT 41800 PHASE 3: HTTP VARIANTS  {host}:{port}  {ts()}")
    log(f"plan: {len(probes)} probes, {timeout}s timeout, {inter_sleep}s between")

    hits = []
    for name, req in probes:
        resp = probe(log, host, port, timeout, inter_sleep, name, req)
        if resp and len(resp) > 0:
            hits.append((name, len(resp)))

    banner(log, f"SUMMARY  {ts()}")
    if hits:
        for name, sz in hits:
            log(f"  *** {name}: GOT {sz} BYTES ***")
    else:
        log("  No responses from any probe")
    log(f"\nLog: {log_path}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
