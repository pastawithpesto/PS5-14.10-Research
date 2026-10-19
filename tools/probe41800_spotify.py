#!/usr/bin/env python3
"""Spotify Connect ZeroConf probe on TCP 41800.

Phase 1 used standard HTTP paths and got 0 bytes.
Spotify Connect ZeroConf uses ?action= query parameters on GET /.
This probe tries the actual Spotify protocol.

Rules: one connection at a time, 5s timeouts, 2s between probes, append-only log.
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


DDP_PAYLOAD = b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n\x00"


def ddp_check(log, host, label):
    banner(log, f"DDP CHECK ({label})  {ts()}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(DDP_PAYLOAD, (host, 9302))
        data, addr = s.recvfrom(8192)
        log(f"  ALIVE: {data.decode('utf-8', 'replace').strip()}")
        s.close()
        return True
    except Exception as e:
        log(f"  NO REPLY: {e}")
        s.close()
        return False


def probe(log, host, port, timeout, name, request_bytes):
    banner(log, f"PROBE: {name}  {ts()}")
    log(f"  REQ: {request_bytes[:200]!r}")
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
            try:
                decoded = data.decode("utf-8", "replace")
                for ln in decoded.splitlines():
                    log(f"    | {ln}")
            except Exception:
                log(f"    | (raw) {data[:500]!r}")
        else:
            log(f"  RESPONSE: 0 bytes (closed in {rt:.1f}ms)")
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
        time.sleep(2.0)


def get_req(host, port, path, extra_headers=None):
    lines = [f"GET {path} HTTP/1.1"]
    lines.append(f"Host: {host}:{port}")
    if extra_headers:
        lines.extend(extra_headers)
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii")


def post_req(host, port, path, body, content_type="application/x-www-form-urlencoded", extra_headers=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    lines = [f"POST {path} HTTP/1.1"]
    lines.append(f"Host: {host}:{port}")
    lines.append(f"Content-Type: {content_type}")
    lines.append(f"Content-Length: {len(body)}")
    if extra_headers:
        lines.extend(extra_headers)
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii") + body


def main():
    parser = argparse.ArgumentParser(description="Spotify Connect ZeroConf probe on TCP 41800")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    timeout = 5.0
    log_path = args.log or os.path.join(os.getcwd(), "port41800-spotify-probes.log")
    log = make_logger(log_path)

    gr = lambda path, **kw: get_req(host, port, path, **kw)
    pr = lambda path, body, **kw: post_req(host, port, path, body, **kw)

    probes = [
        ("spotify-getInfo", gr("/?action=getInfo")),
        ("spotify-getInfo-version", gr("/?action=getInfo&version=2.7.1")),
        ("spotify-addUser-empty", gr("/?action=addUser")),
        ("spotify-addUser-params",
         gr("/?action=addUser&userName=test&blob=dGVzdA==&clientKey=dGVzdA==")),
        ("spotify-resetUsers", gr("/?action=resetUsers")),
        ("spotify-removeUser", gr("/?action=removeUser")),
        ("spotify-getMetadata", gr("/?action=getMetadata")),
        ("spotify-post-getInfo", pr("/", "action=getInfo")),
        ("spotify-post-addUser",
         pr("/", "action=addUser&userName=test&blob=dGVzdA==&clientKey=dGVzdA==")),
        ("bare-get-action", b"GET /?action=getInfo HTTP/1.0\r\n\r\n"),
        ("bare-get-root", b"GET / HTTP/1.0\r\n\r\n"),
        ("raw-getinfo-json", b'{"action":"getInfo"}\n'),
        ("raw-newline", b'\n'),
        ("raw-zero", b'\x00'),
        ("spotify-cseq",
         b"GET / HTTP/1.1\r\nHost: " + f"{host}:{port}".encode() +
         b"\r\nCSeq: 1\r\nContent-Type: application/x-www-form-urlencoded\r\n" +
         b"Connection: close\r\n\r\naction=getInfo\r\n"),
    ]

    banner(log, f"SPOTIFY 41800 PROBE SESSION  target {host}:{port}  {ts()}")
    log(f"plan: {len(probes)} probes, {timeout}s timeout, 2s between")

    ddp_check(log, host, "PRE")

    for name, req in probes:
        resp = probe(log, host, port, timeout, name, req)
        if resp and len(resp) > 50:
            log(f"  *** GOT SUBSTANTIAL RESPONSE ({len(resp)} bytes) ***")

    ddp_check(log, host, "POST")
    banner(log, f"SESSION END  {ts()}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
