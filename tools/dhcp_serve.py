#!/usr/bin/env python3
"""dhcp_serve.py — Single-client DHCP responder for PS5 direct-cable research.

Binds to a specific interface via SO_BINDTODEVICE (requires root), answers
ONLY the specified MAC address, and implements RFC 2131 DORA + DECLINE/RELEASE/
INFORM with proper state machines.

Usage:
  sudo python3 dhcp_serve.py \\
    --iface enp1s0 \\
    --iface-ip 192.168.1.1 \\
    --offer-ip 192.168.1.10 \\
    --allowed-mac aa:bb:cc:dd:ee:ff

Env overrides: DHCP_IFACE, DHCP_LOG, DHCP_PID, DHCP_ACK_UNICAST_TRIAL.
"""
import argparse
import ipaddress
import os
import socket
import struct
import time

SUBNET = "255.255.255.0"
LEASE = 3600

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE = 1, 2, 3, 4, 5, 6, 7
INFORM = 8
MTYPE_NAME = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
DECLINE_RETRY = LEASE

def_log_holder = {}


def log(msg):
    fh = def_log_holder.get("fh")
    try:
        fh.write(msg + "\n")
    except (OSError, ValueError):
        try:
            fh.close()
        except Exception:
            pass
        try:
            def_log_holder["fh"] = open(os.devnull, "a")
            def_log_holder["fh"].write(msg + "\n")
        except Exception:
            pass
    try:
        print(msg, flush=True)
    except (OSError, ValueError):
        pass


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b[:6])


def opt(t, payload):
    return bytes([t, len(payload)]) + payload


def cid_opt(cid):
    return opt(61, cid) if cid else b""


def compute_broadcast(iface_ip, subnet):
    net = ipaddress.ip_network(f"{iface_ip}/{subnet}", strict=False)
    return str(net.broadcast_address)


def main():
    parser = argparse.ArgumentParser(description="Single-client DHCP responder for PS5 research")
    parser.add_argument("--iface", required=True, help="Network interface (e.g. enp1s0)")
    parser.add_argument("--iface-ip", required=True, help="Interface IP address (e.g. 192.168.1.1)")
    parser.add_argument("--offer-ip", required=True, help="IP to offer to the client (e.g. 192.168.1.10)")
    parser.add_argument("--allowed-mac", required=True, help="Only respond to this MAC (e.g. aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--subnet", default=SUBNET, help="Subnet mask (default: 255.255.255.0)")
    args = parser.parse_args()

    iface = os.environ.get("DHCP_IFACE", args.iface)
    iface_ip = args.iface_ip
    offer_ip = args.offer_ip
    allowed_mac = args.allowed_mac.lower()
    subnet = args.subnet
    net_bcast = compute_broadcast(iface_ip, subnet)

    log_path = os.environ.get("DHCP_LOG", os.path.join(os.getcwd(), "dhcp.log"))
    pid_path = os.environ.get("DHCP_PID", os.path.join(os.getcwd(), "dhcp.pid"))

    try:
        def_log_holder["fh"] = open(log_path, "a", buffering=1)
    except OSError:
        def_log_holder["fh"] = open(os.devnull, "a")
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))

    def sid_opt():
        return opt(54, socket.inet_aton(iface_ip))

    def build(xid, chaddr, mtype, yiaddr=None, flags=b"\x00\x00",
              extra_opts=b"", client_id=None):
        if yiaddr is None:
            yiaddr = offer_ip
        p = bytearray(240)
        p[0], p[1], p[2], p[3] = 2, 1, 6, 0
        p[4:8] = xid
        flag_int = 0
        if mtype == NAK:
            flag_int = 0x8000
        else:
            try:
                flag_int = int.from_bytes(flags, "big") & 0x8000
            except Exception:
                flag_int = 0
        p[10:12] = struct.pack("!H", flag_int)
        p[12:16] = socket.inet_aton("0.0.0.0")
        if chaddr:
            p[28:34] = chaddr[:6]
        p[236:240] = b"\x63\x82\x53\x63"
        p[16:20] = socket.inet_aton("0.0.0.0" if mtype in (NAK, INFORM) else yiaddr)
        p[20:24] = socket.inet_aton("0.0.0.0" if mtype == NAK else iface_ip)
        if mtype == NAK:
            opts = bytes([53, 1, NAK]) + sid_opt() + cid_opt(client_id) + b"\xff"
        elif mtype == INFORM:
            opts = bytes([53, 1, ACK]) + sid_opt() + extra_opts + b"\xff"
        else:
            opts = bytes([53, 1, mtype]) + sid_opt() + extra_opts + b"\xff"
        if client_id and mtype != NAK:
            opts = opts[:-1] + cid_opt(client_id) + b"\xff"
        body = bytes(p) + opts
        if len(body) < 300:
            deficit = 300 - len(body)
            body = body[:-1] + b"\x00" * deficit + body[-1:]
        return body

    def parse(data):
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            return None
        if data[0] != 1 or data[1] != 1 or data[2] != 6 or data[3] != 0:
            return None
        if any(data[24:28]):
            return None
        opts = {}
        buf = data[240:]
        i = 0
        try:
            while i < len(buf):
                t = buf[i]
                if t == 255:
                    break
                if t == 0:
                    i += 1
                    continue
                if i + 2 > len(buf):
                    return None
                l = buf[i + 1]
                if i + 2 + l > len(buf):
                    return None
                if t == 53 and l != 1:
                    return None
                if t == 61 and l == 0:
                    return None
                if t not in opts:
                    opts[t] = buf[i + 2:i + 2 + l]
                i += 2 + l
        except IndexError:
            return None
        mt = opts.get(53)
        return {
            "mtype": mt[0] if mt else None,
            "xid": data[4:8],
            "chaddr": data[28:34][:6],
            "ciaddr": socket.inet_ntoa(data[12:16]),
            "flags": data[10:12],
            "opts": opts,
        }

    def opt_ip(opts, code):
        b = opts.get(code)
        if b is None or len(b) != 4:
            return None
        try:
            return socket.inet_ntoa(b)
        except OSError:
            return None

    def requested_opts_available(opts, exclude=()):
        prl = opts.get(55)
        known = {
            1: lambda: opt(1, socket.inet_aton(subnet)),
            3: lambda: opt(3, socket.inet_aton(iface_ip)),
            6: lambda: opt(6, socket.inet_aton(iface_ip)),
            28: lambda: opt(28, socket.inet_aton(net_bcast)),
            54: lambda: sid_opt(),
            51: lambda: opt(51, LEASE.to_bytes(4, "big")),
        }
        parts = b""
        mandatory = [c for c in (54, 51, 1, 3, 6) if c not in exclude]
        emission = mandatory + [c for c in (prl or []) if c in known]
        seen = set()
        for code in emission:
            if code not in seen and code not in exclude:
                seen.add(code)
                parts += known[code]()
        return parts

    def in_our_subnet(ip):
        try:
            n, m, base = (struct.unpack("!I", socket.inet_aton(x))[0] for x in (ip, subnet, iface_ip))
            return n & m == base & m
        except OSError:
            return False

    def decide(msg, declined_at):
        mtype = msg["mtype"]
        ciaddr = msg["ciaddr"]
        now = time.monotonic()
        def quarantined():
            return now - declined_at.get(offer_ip, -1e9) < DECLINE_RETRY

        if mtype == DISCOVER:
            if quarantined():
                return ("IGNORE", None, f"DISCOVER: {offer_ip} in DECLINE quarantine")
            return ("OFFER", offer_ip, "DISCOVER")
        if mtype == DECLINE:
            server_id = opt_ip(msg["opts"], 54)
            requested = opt_ip(msg["opts"], 50)
            if server_id != iface_ip or requested != offer_ip:
                return ("IGNORE", None, "DECLINE without our server-id / pool address")
            return ("DECLINE_OK", offer_ip, "DECLINE: pool address recorded as conflicted")
        if mtype == RELEASE:
            if opt_ip(msg["opts"], 54) and opt_ip(msg["opts"], 54) != iface_ip:
                return ("IGNORE", None, "RELEASE for foreign server-id")
            return ("RELEASE_OK", ciaddr, f"RELEASE: ciaddr {ciaddr}")
        if mtype == INFORM:
            return ("INFORM", None, "INFORM: ACK without lease (RFC 2131 4.3.5)")
        if mtype != REQUEST:
            return ("IGNORE", None, f"unhandled message type {mtype} ({MTYPE_NAME.get(mtype, '?')})")

        server_id = opt_ip(msg["opts"], 54)
        requested = opt_ip(msg["opts"], 50)

        if server_id is not None:
            if server_id != iface_ip:
                return ("IGNORE", None, f"SELECTING: foreign server-id {server_id}")
            if requested is None:
                return ("IGNORE", None, "SELECTING for us without option 50")
            if requested == offer_ip:
                if quarantined():
                    return ("NAK", None, "SELECTING for pool address but quarantined -> NAK")
                return ("ACK", offer_ip, "SELECTING for us: ACK requested pool address")
            return ("NAK", None, f"SELECTING: requested {requested} is not the pool address")

        if ciaddr != "0.0.0.0":
            if ciaddr == offer_ip:
                if quarantined():
                    return ("NAK", None, "RENEW of quarantined address -> NAK")
                return ("ACK", offer_ip, f"RENEW/REBIND: ciaddr {ciaddr}")
            return ("NAK", None, f"RENEW/REBIND: ciaddr {ciaddr} is not the pool address")

        if requested is not None:
            if requested == offer_ip:
                if quarantined():
                    return ("NAK", None, "INIT-REBOOT of quarantined address -> NAK")
                return ("ACK", offer_ip, "INIT-REBOOT: ACK requested pool address")
            if in_our_subnet(requested):
                return ("NAK", None, f"INIT-REBOOT: requested {requested} not pool -> NAK")
            return ("NAK", None, f"INIT-REBOOT: requested {requested} is from a foreign subnet -> NAK")

        return ("IGNORE", None, "REQUEST without server-id, requested-IP and ciaddr")

    def check_iface_ip():
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            data = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface[:15].encode()))
            ip = socket.inet_ntoa(data[20:24])
            return ip == iface_ip, ip
        except Exception as e:
            return None, str(e)
        finally:
            s.close()

    ACK_UNICAST_TRIAL = bool(os.environ.get("DHCP_ACK_UNICAST_TRIAL"))

    def _cksum(data):
        if len(data) % 2:
            data += b"\x00"
        total = sum((data[i] << 8) | data[i+1] for i in range(0, len(data), 2))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def iface_mac():
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            data = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface[:15].encode()))
            return data[18:24]
        except Exception:
            return None
        finally:
            s.close()

    def send_ip_unicast(sock, reply, dst_mac):
        mac = iface_mac()
        if not mac:
            return False
        src_ip = socket.inet_aton(iface_ip)
        dst_ip = socket.inet_aton(offer_ip)
        udp_len = 8 + len(reply)
        udp = struct.pack("!HHHH", 67, 68, udp_len, 0) + reply
        total_len = 20 + udp_len
        iphdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, 17, 0, src_ip, dst_ip)
        iphdr = iphdr[:10] + struct.pack("!H", _cksum(iphdr)) + iphdr[12:]
        frame = dst_mac + mac + b"\x08\x00" + iphdr + udp
        try:
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            raw.bind((iface, 0))
            raw.send(frame)
            raw.close()
            return True
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            return False

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not hasattr(socket, "SO_BINDTODEVICE"):
        print("FATAL: SO_BINDTODEVICE unavailable; refusing to serve on all interfaces", flush=True)
        raise SystemExit(1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (iface + "\0").encode())
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(("0.0.0.0", 67))
    except PermissionError:
        print("FATAL: bind(:67) denied — run as root (SO_BINDTODEVICE also requires root)", flush=True)
        raise SystemExit(1)
    ok, probe_result = check_iface_ip()
    if ok is False:
        print(f"FATAL: {iface} holds {probe_result}, expected {iface_ip} — refusing to serve a dead link", flush=True)
        raise SystemExit(2)
    if ok is None:
        print(f"WARN: could not probe {iface} ({probe_result}) — verify {iface_ip} manually", flush=True)
    print(f"DHCP on :67 dev {iface} (only {allowed_mac}) -> {offer_ip}, dns/router {iface_ip}", flush=True)

    declined_at = {}
    _bcast = ("255.255.255.255", 68)

    def tx(reply):
        try:
            s.sendto(reply, _bcast)
        except OSError as e:
            log(f"{time.strftime('%H:%M:%S')} SOCKERR send {e.__class__.__name__}")

    while True:
        try:
            data, addr = s.recvfrom(2048)
        except OSError as e:
            log(f"{time.strftime('%H:%M:%S')} SOCKERR recv {e.__class__.__name__}")
            continue
        msg = parse(data)
        if msg is None:
            log(f"{time.strftime('%H:%M:%S')} DROP malformed from {addr}")
            continue
        mac = mac_str(msg["chaddr"])
        if mac != allowed_mac:
            log(f"{time.strftime('%H:%M:%S')} IGNORE foreign-mac {mac}")
            continue
        action, ip, reason = decide(msg, declined_at)
        ts = time.strftime("%H:%M:%S")
        cid = msg["opts"].get(61)
        try:
            if action == "OFFER":
                log(f"{ts} OFFER {ip} -> {mac} ({reason})")
                extras = requested_opts_available(msg["opts"], exclude=(54,))
                reply = build(msg["xid"], msg["chaddr"], OFFER, offer_ip,
                              flags=msg["flags"], extra_opts=extras, client_id=cid)
                if reason.startswith("RENEW/REBIND"):
                    try:
                        s.sendto(reply, (msg["ciaddr"], 68))
                    except OSError:
                        tx(reply)
                else:
                    tx(reply)
            elif action == "ACK":
                log(f"{ts} ACK {ip} -> {mac} ({reason})")
                extras = requested_opts_available(msg["opts"], exclude=(54,))
                reply = build(msg["xid"], msg["chaddr"], ACK, ip,
                              flags=msg["flags"], extra_opts=extras, client_id=cid)
                if reason.startswith("RENEW/REBIND"):
                    try:
                        s.sendto(reply, (msg["ciaddr"], 68))
                    except OSError:
                        tx(reply)
                elif ACK_UNICAST_TRIAL and not (int.from_bytes(msg["flags"], "big") & 0x8000):
                    log(f"{ts} ACK-TRIAL unicast {offer_ip} -> {mac}")
                    if not send_ip_unicast(s, reply, msg["chaddr"]):
                        log(f"{ts} ACK-TRIAL fallback broadcast")
                        tx(reply)
                else:
                    tx(reply)
            elif action == "INFORM":
                log(f"{ts} INFORM -> {mac} ({reason})")
                extras = requested_opts_available(msg["opts"], exclude=(51, 53, 54))
                s.sendto(build(msg["xid"], msg["chaddr"], INFORM, yiaddr="0.0.0.0",
                         flags=msg["flags"], extra_opts=extras, client_id=cid),
                         (msg["ciaddr"], 68))
            elif action == "NAK":
                log(f"{ts} NAK -> {mac} ({reason})")
                tx(build(msg["xid"], msg["chaddr"], NAK, client_id=cid))
            elif action == "DECLINE_OK":
                declined_at[offer_ip] = time.monotonic()
                log(f"{ts} DECLINE_OK ({reason}) — no reply (RFC 2131 4.3.3)")
            elif action == "RELEASE_OK":
                log(f"{ts} RELEASE ({reason}) — no reply (RFC 2131 4.3.4)")
            else:
                log(f"{ts} IGNORE -> {mac} ({reason})")
        except Exception as e:
            log(f"{ts} HANDLER-ERR {e.__class__.__name__}: {e}")


if __name__ == "__main__":
    main()
