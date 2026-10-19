#!/usr/bin/env python3
"""dns_serve.py — DNS interceptor for PS5 LAN research.

Spoofs manuals.playstation.net to a local IP, blocks vendor telemetry
domains (NXDOMAIN), and forwards everything else to an upstream resolver.
Supports EDNS, TC→TCP fallback, and BADVERS.

Usage:
  sudo python3 dns_serve.py --bind 192.168.1.1 --spoof-ip 192.168.1.1
  python3 dns_serve.py --bind 127.0.0.1 --port 5353   # unprivileged test

Env overrides: DNS_UPSTREAM (default 9.9.9.9), DNS_LOG, DNS_PID.
"""
import argparse
import os
import socket
import socketserver
import struct
import sys
import threading
import time

EDNS_PAYLOAD = 4096
MAX_DGRAM = 65535
UDP_RESP_LIMIT_DEFAULT = 512

LOG = None
SPOOF_IP = None
SPOOF_NAMES = {"manuals.playstation.net"}
BLOCK_SUBSTRINGS = ("playstation", "sonyentertainmentnetwork", "scea")
UPSTREAM = None


def response_flags(data, aa=False, rcode=0, ra=True):
    try:
        q = int.from_bytes(data[2:4], "big")
        rd = q & 0x0100
    except Exception:
        rd = 0
    f = 0x8000 | rd | (0x0400 if aa else 0) | (0x0080 if ra else 0) | (rcode & 0xF)
    return f


def header(tid, flags, qd=0, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", int.from_bytes(tid, "big"), flags, qd, an, ns, ar)


def opt_record(ttl=0):
    return b"\x00" + struct.pack("!HHIH", 41, EDNS_PAYLOAD, ttl, 0)


def parse_question(data):
    try:
        if len(data) < 17:
            return None
        qflags = int.from_bytes(data[2:4], "big")
        if qflags & 0x8000:
            return None
        if qflags & 0x7800:
            return None
        if int.from_bytes(data[4:6], "big") != 1:
            return None
        i = 12
        labels = []
        while True:
            l = data[i]
            if l == 0:
                i += 1
                break
            if l & 0xC0:
                return None
            if i + 1 + l > len(data):
                return None
            labels.append(data[i + 1:i + 1 + l].decode("ascii", "replace"))
            i += 1 + l
        if i + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[i:i + 4])
        return ".".join(labels).lower(), i + 4, qtype, qclass, qflags
    except Exception:
        return None


def query_opt(data, qend):
    try:
        an, ns, ar = struct.unpack("!HHH", data[6:12])
        i = qend
        count = an + ns + ar
        while count > 0 and i < len(data):
            while True:
                l = data[i]
                if l == 0:
                    i += 1
                    break
                if (l & 0xC0) == 0xC0:
                    i += 2
                    break
                if l & 0xC0:
                    return None
                if i + 1 + l > len(data):
                    return None
                i += 1 + l
            if i + 10 > len(data):
                return None
            typ, cls, ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
            i += 10
            count -= 1
            if typ == 41:
                ver = (ttl >> 16) & 0xFF
                return {"ttl": ttl, "ver": ver, "do": bool(ttl & 0x00008000),
                        "size": cls}
            if i + rdlen > len(data):
                return None
            i += rdlen
    except Exception:
        return None
    return None


def build_reply(data, qend, ip, qflags, edns):
    tid = data[:2]
    qd = data[12:qend]
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    if edns:
        reply_ttl = 0x00008000 if edns.get("do") else 0
        return header(tid, response_flags(data, aa=True, rcode=0), qd=1, an=1, ar=1) \
             + qd + rr + opt_record(reply_ttl)
    return header(tid, response_flags(data, aa=True, rcode=0), qd=1, an=1) + qd + rr


def tc_reply(data, qend, rcode=0):
    f = response_flags(data, rcode=rcode) | 0x0200
    return header(data[:2], f, qd=1) + data[12:qend]


def nx_domain(data, qend, qflags, edns):
    f = response_flags(data, rcode=3, ra=False)
    qd = data[12:qend]
    if edns:
        return header(data[:2], f, qd=1, ar=1) + qd + opt_record(edns["ttl"] & 0x80000000)
    return header(data[:2], f, qd=1) + qd


def no_data(data, qend, qflags, edns):
    f = response_flags(data, rcode=0)
    qd = data[12:qend]
    if edns:
        return header(data[:2], f, qd=1, ar=1) + qd + opt_record(edns["ttl"] & 0x80000000)
    return header(data[:2], f, qd=1) + qd


def serv_fail(data, qend, qflags, edns):
    f = response_flags(data, rcode=2)
    qd = data[12:qend]
    if edns:
        return header(data[:2], f, qd=1, ar=1) + qd + opt_record(edns["ttl"] & 0x80000000)
    return header(data[:2], f, qd=1) + qd


def bad_vers(data, qend):
    tid = data[:2]
    return header(tid, response_flags(data, rcode=0), qd=1, ar=1) \
         + data[12:qend] + opt_record(0x01000000)


def tc_flag(data):
    try:
        return int.from_bytes(data[2:4], "big") & 0x0200
    except Exception:
        return 0


def forward_tcp(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    deadline = time.monotonic() + 3
    s.settimeout(3)
    try:
        s.connect(UPSTREAM)
        s.sendall(struct.pack("!H", len(data)) + data)
        hdr = b""
        while len(hdr) < 2 and time.monotonic() < deadline:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        want = int.from_bytes(hdr, "big")
        if not (12 <= want <= MAX_DGRAM):
            return None
        msg = b""
        while len(msg) < want and time.monotonic() < deadline:
            chunk = s.recv(min(65535, want - len(msg)))
            if not chunk:
                return None
            msg += chunk
        return msg
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def forward(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.connect(UPSTREAM)
        s.sendto(data, UPSTREAM)
        while True:
            d = s.recv(MAX_DGRAM)
            if len(d) >= 12 and d[0:2] == data[0:2] and (d[2] & 0x80):
                break
        if tc_flag(d):
            full = forward_tcp(data)
            if full and full[0:2] == data[0:2] and (full[2] & 0x80):
                return full
            return d
        return d
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def safe_log(line):
    try:
        LOG.write(line)
    except (OSError, ValueError, AttributeError):
        pass


class Limiter:
    sem = threading.Semaphore(64)


def client_udp_limit(edns):
    if not edns:
        return UDP_RESP_LIMIT_DEFAULT
    size = edns.get("size") or 0
    if size < 512:
        return 512
    if size > MAX_DGRAM - 20:
        return MAX_DGRAM - 20
    return size


def split_q(data):
    try:
        qd = int.from_bytes(data[4:6], "big")
        if qd != 1:
            return None
        i = 12
        while True:
            l = data[i]
            if l == 0:
                i += 1
                break
            if (l & 0xC0) == 0xC0:
                i += 2
                break
            if l & 0xC0:
                return None
            if i + 1 + l > len(data):
                return None
            i += 1 + l
        if i + 4 > len(data):
            return None
        return i + 4
    except Exception:
        return None


def udp_safe(resp, limit):
    if len(resp) <= limit:
        return resp
    qend = split_q(resp)
    if qend is None:
        return None
    return tc_reply(resp, qend, rcode=int.from_bytes(resp[2:4], "big") & 0xF)


def respond(data, tcp=False):
    q = parse_question(data)
    if q is None:
        return None
    name, qend, qtype, qclass, qflags = q
    if qclass != 1:
        return None
    edns = query_opt(data, qend)
    if edns and edns.get("ver"):
        return bad_vers(data, qend)
    safe_log(f"{time.strftime('%H:%M:%S')} {name} t={qtype} edns={bool(edns)}\n")
    if name in SPOOF_NAMES:
        if qtype == 1:
            return build_reply(data, qend, SPOOF_IP, qflags, edns)
        return no_data(data, qend, qflags, edns)
    if any(b in name for b in BLOCK_SUBSTRINGS):
        safe_log(f"{time.strftime('%H:%M:%S')} X BLOCKED {name}\n")
        return nx_domain(data, qend, qflags, edns)
    r = forward(data)
    if r is None:
        return serv_fail(data, qend, qflags, edns)
    if tcp:
        return r
    return udp_safe(r, client_udp_limit(edns))


class H(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if not Limiter.sem.acquire(timeout=5):
            return
        try:
            out = respond(data)
            if out:
                try:
                    sock.sendto(out, self.client_address)
                except OSError:
                    return
        finally:
            Limiter.sem.release()


class T(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        try:
            hdr = b""
            while len(hdr) < 2:
                chunk = self.request.recv(2 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            want = int.from_bytes(hdr, "big")
            if not (12 <= want <= MAX_DGRAM):
                return
            buf = b""
            while len(buf) < want:
                chunk = self.request.recv(min(65535, want - len(buf)))
                if not chunk:
                    return
                buf += chunk
            if not Limiter.sem.acquire(timeout=5):
                return
            try:
                out = respond(buf, tcp=True)
            finally:
                Limiter.sem.release()
            if out:
                self.request.sendall(struct.pack("!H", len(out)) + out)
        except Exception:
            return


class S(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    max_packet_size = MAX_DGRAM


class ST(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main():
    global LOG, SPOOF_IP, UPSTREAM

    parser = argparse.ArgumentParser(description="DNS interceptor for PS5 LAN research")
    parser.add_argument("--bind", required=True, help="IP address to bind to (e.g. your host's LAN IP)")
    parser.add_argument("--port", type=int, default=53, help="DNS port (default: 53, use 5353 for unprivileged)")
    parser.add_argument("--spoof-ip", default=None, help="IP to return for spoofed names (default: same as --bind)")
    parser.add_argument("--upstream", default=None, help="Upstream DNS resolver (default: 9.9.9.9, env: DNS_UPSTREAM)")
    parser.add_argument("--log", default=None, help="Log file path (default: ./dns-queries.log, env: DNS_LOG)")
    parser.add_argument("--pid", default=None, help="PID file path (default: ./dns.pid, env: DNS_PID)")
    args = parser.parse_args()

    bind_addr = args.bind
    port = args.port
    SPOOF_IP = args.spoof_ip or bind_addr
    upstream_ip = args.upstream or os.environ.get("DNS_UPSTREAM", "9.9.9.9")
    UPSTREAM = (upstream_ip, 53)
    log_path = args.log or os.environ.get("DNS_LOG", os.path.join(os.getcwd(), "dns-queries.log"))
    pid_path = args.pid or os.environ.get("DNS_PID", os.path.join(os.getcwd(), "dns.pid"))

    try:
        LOG = open(log_path, "a", buffering=1)
    except OSError:
        LOG = open(os.devnull, "a")
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))

    udp = S((bind_addr, port), H)
    tcp = ST((bind_addr, port), T)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print(f"DNS on {bind_addr}:{port} (override manuals.playstation.net -> {SPOOF_IP}, "
          f"vendor domains -> NXDOMAIN, rest forwarded to {upstream_ip}, "
          f"EDNS echoed, TC->TCP both directions)", flush=True)
    udp.serve_forever()


if __name__ == "__main__":
    main()
