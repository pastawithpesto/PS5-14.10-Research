#!/usr/bin/env python3
"""Bounded, non-concurrent probe of TCP 41800 on a PS5.

Rules implemented:
- one connection at a time, NO concurrency
- 3s connect/recv timeouts, 2s sleep between probes
- fixed request list only (no fuzzing beyond the plan)
- every exchange logged raw (request bytes, response bytes, timing)
- DDP (UDP 9302 SRCH) liveness check before and after the probe session
"""
import argparse
import socket
import time
import datetime
import os

DDP_PORT = 9302
TIMEOUT = 3.0
INTER_PROBE_SLEEP = 2.0

DDP_PAYLOAD = b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n\x00"


def make_logger(log_path):
    def log(line=""):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return log


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " local"


def banner(log, title):
    log()
    log("=" * 78)
    log(f"== {title}")
    log("=" * 78)


def ddp_check(log, host, label):
    banner(log, f"DDP LIVENESS CHECK ({label})  UDP {host}:{DDP_PORT}  {ts()}")
    log(f"REQUEST (repr): {DDP_PAYLOAD!r}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    t0 = time.time()
    replies = []
    try:
        s.sendto(DDP_PAYLOAD, (host, DDP_PORT))
        log(f"  send: OK at +{(time.time()-t0)*1000:.1f} ms")
        while True:
            try:
                data, addr = s.recvfrom(8192)
                replies.append((addr, data, time.time() - t0))
            except socket.timeout:
                break
    except OSError as e:
        log(f"  ERROR: {type(e).__name__}: {e}")
    finally:
        s.close()
    if replies:
        for i, (addr, data, dt) in enumerate(replies, 1):
            log(f"REPLY {i} from {addr[0]}:{addr[1]} at +{dt*1000:.1f} ms ({len(data)} bytes):")
            log(f"  {data!r}")
            log(f"  decoded: {data.decode('utf-8', 'replace')!r}")
        log(f"DDP RESULT ({label}): {len(replies)} reply(ies) -> console ALIVE and answering DDP")
    else:
        log(f"DDP RESULT ({label}): NO reply within {TIMEOUT}s -> console NOT answering DDP (STOP CONDITION if unexpected)")
    return len(replies)


def probe(log, host, port, name, request_bytes, delay=INTER_PROBE_SLEEP):
    banner(log, f"PROBE: {name}  {ts()}")
    log("REQUEST:")
    log(f"  {request_bytes!r}")
    n_lines = request_bytes.count(b"\r\n")
    log(f"  ({len(request_bytes)} bytes, {n_lines} CRLF lines)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    t0 = time.time()
    try:
        s.connect((host, port))
        log(f"  connect: OK in {(time.time()-t0)*1000:.1f} ms")
        t1 = time.time()
        s.sendall(request_bytes)
        log(f"  sendall: OK ({len(request_bytes)} bytes) in {(time.time()-t1)*1000:.1f} ms")
        data = b""
        t2 = time.time()
        closed_by_peer = False
        timed_out = False
        try:
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    closed_by_peer = True
                    break
                data += chunk
        except socket.timeout:
            timed_out = True
        rtt = (time.time() - t2) * 1000
        if closed_by_peer:
            log(f"  recv: EOF (server closed the connection) at +{rtt:.1f} ms after send")
        elif timed_out:
            log(f"  recv: TIMEOUT {TIMEOUT}s — server sent NOTHING (silent)")
        if data:
            log(f"RESPONSE: {len(data)} bytes, first byte at +{rtt:.1f} ms")
            log(f"  {data!r}")
            log("  decoded:")
            for ln in data.decode("utf-8", "replace").splitlines():
                log(f"    | {ln}")
        else:
            log("RESPONSE: <0 bytes received>")
        t3 = time.time()
        try:
            s.close()
        except OSError:
            pass
        log(f"  probe socket closed locally; total probe wall time {(time.time()-t0)*1000:.1f} ms")
    except OSError as e:
        log(f"  ERROR: {type(e).__name__}: {e}")
        try:
            s.close()
        except OSError:
            pass
    if delay:
        time.sleep(delay)


def std_request(host, port, method, path, version="HTTP/1.1", extra_headers=None, host_header=None, omit_host=False, body=b""):
    lines = [f"{method} {path} {version}"]
    if not omit_host:
        hh = host_header if host_header is not None else f"{host}:{port}"
        if version == "HTTP/1.1" or host_header is not None:
            lines.append(f"Host: {hh}")
    if extra_headers:
        lines.extend(extra_headers)
    if method == "POST" and "Content-Length" not in (extra_headers or []):
        lines.append(f"Content-Length: {len(body)}")
    lines.append("User-Agent: lan-audit-probe/1.0")
    lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("ascii") + body


def main():
    parser = argparse.ArgumentParser(description="Probe TCP 41800 on a PS5")
    parser.add_argument("--ps5-ip", required=True, help="PS5 IP address")
    parser.add_argument("--port", type=int, default=41800, help="Target port (default: 41800)")
    parser.add_argument("--log", default=None, help="Log file path (default: ./port41800-probes.log)")
    args = parser.parse_args()

    host = args.ps5_ip
    port = args.port
    log_path = args.log or os.path.join(os.getcwd(), "port41800-probes.log")
    log = make_logger(log_path)

    sr = lambda method, path, **kw: std_request(host, port, method, path, **kw)

    probes = [
        ("1 OPTIONS /", sr("OPTIONS", "/")),
        ("2 HEAD /", sr("HEAD", "/")),
        ("3 POST / empty body", sr("POST", "/")),
        ("4 GET /index.html", sr("GET", "/index.html")),
        ("5 GET /rp", sr("GET", "/rp")),
        ("6 GET /sie/", sr("GET", "/sie/")),
        ("7 GET /sie/ps5/rp/sess/rgst", sr("GET", "/sie/ps5/rp/sess/rgst")),
        ("8 GET /nonexistent-path-xyz", sr("GET", "/nonexistent-path-xyz")),
        ("9 GET / UA:RemotePlay", sr("GET", "/", extra_headers=["User-Agent: RemotePlay"])),
        ("10 GET / RP-Version: 1.0", sr("GET", "/", extra_headers=["RP-Version: 1.0"])),
        ("11 GET / Host: localhost", sr("GET", "/", host_header="localhost")),
        ("12 GET / HTTP/1.0 (with Host)", sr("GET", "/", version="HTTP/1.0")),
        ("13 GET / HTTP/1.0 no-Host minimal", b"GET / HTTP/1.0\r\n\r\n"),
    ]

    banner(log, f"PORT 41800 PROBE SESSION START  target {host}:{port}  {ts()}")
    log(f"plan: {len(probes)} probes, one TCP connection each, {TIMEOUT}s timeouts, "
        f"{INTER_PROBE_SLEEP}s between probes, no concurrency")

    ddp_pre = ddp_check(log, host, "BEFORE probes")
    if ddp_pre == 0:
        log("!! DDP not answering BEFORE probes — aborting probe session per plan.")
        banner(log, "SESSION ABORTED (DDP pre-check failed)")
        return

    for name, req in probes:
        probe(log, host, port, name, req)

    ddp_check(log, host, "AFTER probes")
    banner(log, f"PORT 41800 PROBE SESSION END  {ts()}")
    print(f"Done. Log: {log_path}")


if __name__ == "__main__":
    main()
