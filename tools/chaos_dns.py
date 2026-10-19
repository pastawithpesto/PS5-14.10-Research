#!/usr/bin/env python3
"""chaos_dns.py — malformed DNS response battery (remote resolver fuzzing).

Rules: manuals.playstation.net ALWAYS gets a normal response (our channel).
Background console queries get a rotating malformed variant, one per query,
logging variant+timestamp. If the console stops querying after variant K,
the resolver crashed = FINDING.

Usage: sudo python3 chaos_dns.py --bind 192.168.1.1
"""
import argparse
import os
import socket
import struct
import threading
import time


SPOOF_NAMES = {"manuals.playstation.net"}


def make_logger(log_path):
    def log(s):
        line = "%s %s" % (time.strftime("%H:%M:%S"), s)
        print(line, flush=True)
        with open(log_path, "a") as f:
            f.write(line + "\n")
    return log


def qname(data):
    out, i = [], 12
    try:
        while True:
            n = data[i]
            if n == 0:
                return ".".join(out).lower(), i + 1
            if n & 0xC0:
                return ".".join(out).lower(), i + 2
            out.append(data[i+1:i+1+n].decode("latin1"))
            i += 1 + n
    except Exception:
        return "", i + 1


def normal_response(data, spoof_ip):
    tid = data[0:2]
    flags = struct.pack("!H", 0x8180)
    qd = data[4:6]
    n, q_end = qname(data)
    question = data[12:q_end+4]
    ans = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) +
           socket.inet_aton(spoof_ip))
    return tid + flags + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_ptr_loop(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    ptr_off = 12 + len(question)
    name_ptr = struct.pack("!H", 0xC000 | ptr_off)
    ans = name_ptr + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_ptr_forward(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    ans = struct.pack("!H", 0xC000 | 0x3FFD) + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_label64(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    big = bytes([64]) + b"A"*64 + b"\x00"
    ans = big + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_ancount_huge(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\xff\xff\x00\x00\x00\x00" + question + ans


def v_trunc_mid(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    ans = b"\xc0\x0c" + struct.pack("!HHI", 1, 1, 60)
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_ptr_into_header(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    ans = struct.pack("!H", 0xC000 | 2) + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + ans


def v_deep_chain(data):
    tid = data[0:2]; qd = data[4:6]
    _, qe = qname(data); question = data[12:qe+4]
    base = 12 + len(question)
    chain = b""
    for i in range(40):
        nxt = base + 2*(i+1)
        chain += struct.pack("!H", 0xC000 | (nxt if nxt < 0x3FFF else 12))
    chain += b"\x00"
    ans = struct.pack("!H", 0xC000 | base) + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    return tid + b"\x81\x80" + qd + b"\x00\x01\x00\x00\x00\x00" + question + chain + ans


VARIANTS = [
    ("PTR-LOOP", v_ptr_loop),
    ("PTR-FORWARD", v_ptr_forward),
    ("LABEL-64", v_label64),
    ("ANCOUNT-HUGE", v_ancount_huge),
    ("TRUNC-MID", v_trunc_mid),
    ("PTR-INTO-HEADER", v_ptr_into_header),
    ("DEEP-CHAIN", v_deep_chain),
]


def main():
    parser = argparse.ArgumentParser(description="Malformed DNS response battery for resolver fuzzing")
    parser.add_argument("--bind", required=True, help="IP address to bind to")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--spoof-ip", default=None, help="IP for spoofed names (default: same as --bind)")
    parser.add_argument("--log", default=None, help="Log file (default: ./chaos-dns.log)")
    args = parser.parse_args()

    bind_addr = args.bind
    port = args.port
    spoof_ip = args.spoof_ip or bind_addr
    log_path = args.log or os.path.join(os.getcwd(), "chaos-dns.log")
    log = make_logger(log_path)

    state = {"i": 0, "lock": threading.Lock()}

    def handle(data, addr, sock):
        name, _ = qname(data)
        if name in SPOOF_NAMES:
            try:
                sock.sendto(normal_response(data, spoof_ip), addr)
            except Exception:
                pass
            return
        with state["lock"]:
            vn, vf = VARIANTS[state["i"] % len(VARIANTS)]
            state["i"] += 1
        try:
            resp = vf(data)
            sock.sendto(resp, addr)
            log("CHAOS %s -> %s (%s) [%d bytes]" % (vn, addr[0], name, len(resp)))
        except Exception as e:
            log("ERR %s: %s" % (vn, e))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, port))
    log("chaos-dns listening on %s:%d — %d variants in rotation" % (bind_addr, port, len(VARIANTS)))
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    main()
