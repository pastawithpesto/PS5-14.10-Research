#!/usr/bin/env python3
"""Port 41800 Phase 4: Method and format enumeration.

Phase 3 key finding: "GET /?action=getInfo\r\n\r\n" (no HTTP version) returns:
  "HTTP/1.1 500 Server Error - Bad request: [GET]"

The server rejects GET by method name, meaning POST or other methods may work.
Any request WITH "HTTP/x.x" gets instant close (0 bytes).
Server only processes requests WITHOUT the HTTP version string.
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
                log("  ** HELD **")
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


PROBES = [
    ("post-bare", b"POST /?action=getInfo\r\n\r\n"),
    ("put-bare", b"PUT /?action=getInfo\r\n\r\n"),
    ("delete-bare", b"DELETE /?action=getInfo\r\n\r\n"),
    ("options-bare", b"OPTIONS /?action=getInfo\r\n\r\n"),
    ("head-bare", b"HEAD /?action=getInfo\r\n\r\n"),
    ("patch-bare", b"PATCH /?action=getInfo\r\n\r\n"),
    ("post-bare-form",
     b"POST /\r\nContent-Type: application/x-www-form-urlencoded\r\n"
     b"Content-Length: 16\r\n\r\naction=getInfo\r\n"),
    ("post-bare-action-path",
     b"POST /?action=getInfo\r\nContent-Length: 0\r\n\r\n"),
    ("post-root", b"POST /\r\n\r\n"),
    ("post-zeroconf", b"POST /ZeroConf\r\n\r\n"),
    ("post-zc-action", b"POST /ZeroConf?action=getInfo\r\n\r\n"),
    ("get-reference", b"GET /?action=getInfo\r\n\r\n"),
    ("spotify-bare", b"SPOTIFY /?action=getInfo\r\n\r\n"),
    ("connect-bare", b"CONNECT /?action=getInfo\r\n\r\n"),
    ("info-bare", b"INFO /?action=getInfo\r\n\r\n"),
    ("play-bare", b"PLAY /?action=getInfo\r\n\r\n"),
    ("post-json-bare",
     b"POST /\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n"
     b'{"action":"getInfo"}'),
    ("post-bare-root-q", b"POST /?action=getInfo\r\n\r\n"),
    ("post-bare-adduser", b"POST /?action=addUser\r\n\r\n"),
    ("post-bare-reset", b"POST /?action=resetUsers\r\n\r\n"),
    ("getinfo-raw", b"getInfo\r\n\r\n"),
    ("action-raw", b"action=getInfo\r\n\r\n"),
]


def main():
    parser = argparse.ArgumentParser(description="Port 41800 Phase 4: Method and format enumeration")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    timeout = 6.0
    inter_sleep = 1.5
    log_path = args.log or os.path.join(os.getcwd(), "port41800-phase4.log")
    log = make_logger(log_path)

    banner(log, f"PORT 41800 PHASE 4: METHOD ENUM  {host}:{port}  {ts()}")
    log(f"plan: {len(PROBES)} probes")

    hits = []
    for name, req in PROBES:
        resp = probe(log, host, port, timeout, inter_sleep, name, req)
        if resp and len(resp) > 0:
            try:
                body = resp.decode("utf-8", "replace")
            except Exception:
                body = ""
            hits.append((name, len(resp), body))

    banner(log, f"SUMMARY  {ts()}")
    for name, sz, body in hits:
        short = body.split("\n")[-2].strip() if body else ""
        log(f"  {name}: {sz} bytes — {short}")
    log(f"\nLog: {log_path}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
