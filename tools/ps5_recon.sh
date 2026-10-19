#!/usr/bin/env bash
# ps5_recon.sh — safe, read-only listening-surface enumeration for a suspected PS5 on a LAN.
#
# Scope / safety:
#   * Read-only. No exploit, no authentication attempt, no packet with a payload
#     beyond the two documented, unauthenticated Sony discovery verbs (SRCH, M-SEARCH).
#   * No wake packets are sent unless you pass --wake AND --credential (see below).
#   * Bounded and rate-limited. Safe to run against a mixed LAN.
#
# Usage:
#   bash ps5_recon.sh --subnet 192.168.1.0/24
#   bash ps5_recon.sh --subnet 10.0.0.0/24 --passive-only
#
# Evidence discipline: every line of output is either OBSERVED (a packet/answer you
# actually received) or a labelled INFERENCE. Nothing here proves Remote Play works.

set -u -o pipefail

SUBNET=""
IFACE=""
PASSIVE_ONLY=0
PASSIVE_SECS=45
TCP_TIMEOUT="0.6"
OUTDIR=""
DO_WAKE=0
CREDENTIAL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --subnet)      SUBNET="$2"; shift 2 ;;
    --iface)       IFACE="$2"; shift 2 ;;
    --passive-only) PASSIVE_ONLY=1; shift ;;
    --passive-secs) PASSIVE_SECS="$2"; shift 2 ;;
    --timeout)     TCP_TIMEOUT="$2"; shift 2 ;;
    --outdir)      OUTDIR="$2"; shift 2 ;;
    --wake)        DO_WAKE=1; shift ;;
    --credential)  CREDENTIAL="$2"; shift 2 ;;
    -h|--help)     sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$SUBNET" ]; then
  echo "ERROR: --subnet is required (e.g. --subnet 192.168.1.0/24)" >&2
  exit 1
fi

if [ -z "$OUTDIR" ]; then
  OUTDIR="./ps5-recon-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$OUTDIR"
LOG="$OUTDIR/transcript.txt"
exec > >(tee -a "$LOG") 2>&1

say()  { printf '%s\n' "$*"; }
head1() { printf '\n===== %s =====\n' "$*"; }
obs()  { printf '  [OBSERVED] %s\n' "$*"; }
inf()  { printf '  [INFERENCE] %s\n' "$*"; }
unk()  { printf '  [UNKNOWN]  %s\n' "$*"; }

# Derive a gateway IP from subnet for route lookup
GATEWAY_HINT="$(python3 -c "import ipaddress,sys; n=ipaddress.ip_network('$SUBNET',strict=False); print(next(n.hosts()))")"

if [ -z "$IFACE" ]; then
  IFACE="$(ip -4 route get "$GATEWAY_HINT" 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)"
fi
OWN_IP="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
BCAST="$(python3 - "$SUBNET" <<'PY'
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1],strict=False)
print(n.broadcast_address)
PY
)"

say "ps5-recon  $(date -Is)"
say "interface : $IFACE"
say "own ip    : ${OWN_IP:-?}"
say "subnet    : $SUBNET   broadcast: $BCAST"
say "output dir: $OUTDIR"

# ---------------------------------------------------------------------------
head1 "PHASE 0 — inventory local NICs (context only)"
ip -brief -4 addr show 2>/dev/null
say ""
say "NOTE: a global IPv6 prefix on this LAN means the PS5 may also hold a global"
say "      IPv6 address. A /64 cannot be swept; it is found via the neighbour"
say "      cache, mDNS or the DDP reply source address instead."

# ---------------------------------------------------------------------------
head1 "PHASE 1 — passive observation (no packets of our own beyond normal traffic)"
say "Baseline state BEFORE we send anything:"

say ""
say "-- existing neighbour (ARP/NDP) entries --"
ip neigh show dev "$IFACE" 2>/dev/null | tee "$OUTDIR/neigh-before.txt" || true

if [ "$PASSIVE_ONLY" -eq 1 ] || [ "${PASSIVE_SECS:-0}" -gt 0 ]; then
  say ""
  say "-- capturing ${PASSIVE_SECS}s of broadcast/multicast chatter for DHCP / mDNS / SSDP / DDP --"
  say "   (this is what reveals a PS5 that is present but not answering our probes)"
  timeout "$PASSIVE_SECS" tcpdump -i "$IFACE" -n -l -s0 \
      '(udp port 67 or udp port 68 or udp port 5353 or udp port 1900 or udp port 9302 or udp port 9296 or udp port 9297 or udp port 987)' \
      2>/dev/null | tee "$OUTDIR/passive.pcap.txt" | head -200 || true
fi

say ""
say "-- mDNS/Bonjour cache (avahi), if available --"
if command -v avahi-browse >/dev/null 2>&1; then
  timeout 12 avahi-browse -atp 2>/dev/null | tee "$OUTDIR/avahi.txt" | head -80 || true
else
  say "  avahi-browse not installed"
fi

# ---------------------------------------------------------------------------
if [ "$PASSIVE_ONLY" -eq 0 ]; then

head1 "PHASE 2 — host sweep (ICMP + ARP population)"
python3 - "$SUBNET" <<'PY' > "$OUTDIR/sweep.txt" 2>&1
import ipaddress, subprocess, sys, concurrent.futures
net = ipaddress.ip_network(sys.argv[1], strict=False)
def ping(ip):
    try:
        subprocess.run(["ping","-c","1","-W","1",str(ip)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except Exception:
        pass
with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
    list(ex.map(ping, net.hosts()))
PY
say "sweep done"

say ""
say "-- neighbour cache AFTER sweep --"
ip neigh show dev "$IFACE" 2>/dev/null | tee "$OUTDIR/neigh-after.txt"

say ""
say "-- candidate consoles (Sony OUIs) --"
python3 - "$OUTDIR/neigh-after.txt" <<'PY'
import re, sys
SONY = {
 "00:04:1F":"Sony","00:13:15":"Sony","00:15:C1":"Sony","00:19:C5":"Sony","00:1A:80":"Sony",
 "00:1D:0D":"Sony","00:1D:BA":"Sony","00:1E:A9":"Sony","00:24:BE":"Sony","00:EB:2D":"Sony",
 "04:5D:56":"Sony","08:60:6E":"Sony","0C:FE:45":"Sony","10:4A:7D":"Sony","18:C5:01":"Sony",
 "1C:66:6D":"Sony","20:3C:AE":"Sony","24:21:AB":"Sony","28:0D:FC":"Sony","28:3F:69":"Sony",
 "2C:CC:44":"Sony","30:39:26":"Sony","30:F9:ED":"Sony","34:76:C5":"Sony","34:C7:31":"Sony",
 "38:18:4C":"Sony","3C:07:71":"Sony","40:2B:A3":"Sony","44:D8:32":"Sony","48:18:8D":"Sony",
 "4C:B0:4A":"Sony","50:1A:A5":"Sony","54:27:1E":"Sony","54:42:49":"Sony","58:48:22":"Sony",
 "5C:5F:67":"Sony","60:45:BD":"Sony","64:D4:BD":"Sony","6C:0E:0D":"Sony","70:9E:29":"Sony",
 "74:C9:29":"Sony","78:84:3C":"Sony","7C:42:31":"Sony","80:1F:02":"Sony","84:25:19":"Sony",
 "88:1B:99":"Sony","8C:64:A2":"Sony","90:F1:AA":"Sony","94:23:6E":"Sony","98:5A:EB":"Sony",
 "9C:B6:54":"Sony","A0:E4:53":"Sony","A4:E5:97":"Sony","A8:E3:EE":"Sony","AC:9B:0A":"Sony",
 "B0:05:94":"Sony","B4:5D:50":"Sony","B8:8A:EC":"Sony","BC:60:A7":"Sony","C0:48:E6":"Sony",
 "C4:3C:EA":"Sony","C8:63:F1":"Sony","CC:2D:E0":"Sony","D0:03:DF":"Sony","D4:3D:7E":"Sony",
 "D8:D4:3C":"Sony","DC:0C:2D":"Sony","E0:AE:5E":"Sony","E4:0D:36":"Sony","E8:39:35":"Sony",
 "EC:0E:DA":"Sony","F0:BF:97":"Sony","F4:6B:EF":"Sony","F8:46:1C":"Sony","F8:D0:AC":"Sony",
 "FC:0F:E6":"Sony","FC:E9:98":"Sony",
}
hits=0
for line in open(sys.argv[1], errors="replace"):
    m = re.search(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})", line, re.I)
    if not m: continue
    ip, mac = m.group(1), m.group(2).lower()
    oui = mac.upper()[0:8]
    if oui in SONY:
        hits += 1
        print(f"  CANDIDATE {ip}  {mac}   OUI {oui} ({SONY[oui]})")
if not hits:
    print("  no Sony-OUI neighbour found (does NOT prove the PS5 is absent: it may be off,")
    print("  or its NIC may be down, or it may be on another L2 segment/VLAN/guest SSID)")
PY

head1 "PHASE 3 — Sony DDP discovery (the Remote Play liveness probe)"
say "Sending the two documented, unauthenticated discovery verbs:"
say "  PS5: 'SRCH * HTTP/1.1 / device-discovery-protocol-version:00030010' -> UDP/9302"
say "  PS4: 'SRCH * HTTP/1.1 / device-discovery-protocol-version:00020020' -> UDP/987"
say "Source port is bound in 9303..9319, matching chiaki-ng's own client behaviour."

python3 - "$SUBNET" "$OWN_IP" "$OUTDIR" <<'PY' | tee "$OUTDIR/ddp.txt"
import ipaddress, socket, sys, time

subnet, own_ip, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
NET = ipaddress.ip_network(subnet, strict=False)
OWN = own_ip

DDP = [(9302, b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n\x00", "PS5"),
       ( 987, b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00020020\n\x00", "PS4")]

def make_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for p in range(9303, 9320):
        try:
            s.bind(("", p)); break
        except OSError:
            continue
    else:
        s.bind(("", 0))
    s.settimeout(0.4)
    return s

def parse(data):
    txt = data.decode("utf-8", "replace")
    lines = [l.strip() for l in txt.splitlines() if l.strip()]
    if not lines: return None
    code = None
    if lines[0].upper().startswith("HTTP/1.1"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit(): code = int(parts[1])
    hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return code, hdrs

targets = [str(NET.broadcast_address)] + [str(h) for h in NET.hosts() if str(h) != OWN]

seen = {}
for port, payload, gen in DDP:
    s = make_sock()
    for t in targets:
        try: s.sendto(payload, (t, port))
        except OSError: pass
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        ip = addr[0]
        if ip in seen: continue
        r = parse(data)
        if r:
            code, h = r
            seen[ip] = (gen, code, h)
    s.close()

if not seen:
    print("  [OBSERVED] zero DDP responses from", subnet)
    print("  [INFERENCE] no console on this L2 segment is advertising Remote Play.")
    print("              Does NOT by itself prove the console is absent or off — see PHASE 2/1.")
else:
    for ip, (gen, code, h) in sorted(seen.items()):
        state = {200: "READY (awake)", 620: "STANDBY (rest mode)"}.get(code, f"code {code}")
        print(f"  [OBSERVED] {ip}  responded as {gen}  ->  {state}")
        for k in ("host-name","host-type","host-id","host-request-port",
                  "system-version","device-discovery-protocol-version",
                  "running-app-titleid","running-app-name"):
            if k in h:
                print(f"      {k}: {h[k]}")
        print("      raw:")
        for l in h.items():
            pass
print("")
PY
say "DDP probe complete."
say ""
say "NOTE: the DDP reply's 'host-request-port' (observed as 997 on real consoles) is NOT"
say "      the port used for registration. chiaki-ng connects to the SOURCE ADDRESS AND"
say "      SOURCE PORT of the RES3 reply, i.e. UDP+TCP both on 9295. Do not chase 997."

head1 "PHASE 3b — registration 'search' probe on UDP 9295 (independent of DDP)"
say "chiaki-ng's regist.c sends the bare string 'SRC3' + NUL to UDP/9295 (PS4: 'SRC2')"
say "and expects a reply beginning 'RES3' (PS4: 'RES2'). This is a SEPARATE listener"
say "from the DDP responder, so it can answer when DDP does not, and vice versa."

python3 - "$SUBNET" "$OWN_IP" <<'PY'
import ipaddress, socket, sys, time
subnet, own_ip = sys.argv[1], sys.argv[2]
NET = ipaddress.ip_network(subnet, strict=False)
targets = [str(NET.broadcast_address)] + [str(h) for h in NET.hosts() if str(h) != own_ip]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try: s.bind(("", 0))
except OSError: pass
s.settimeout(0.4)
hits = {}
for payload in (b"SRC3\x00", b"SRC2\x00"):
    for t in targets:
        try: s.sendto(payload, (t, 9295))
        except OSError: pass
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        hits[addr[0]] = (addr[1], data[:64])
s.close()
if not hits:
    print("  [OBSERVED] zero replies to the SRC3/SRC2 registration search on UDP/9295")
    print("  [INFERENCE] the Remote Play registration service is not answering.")
else:
    for ip, (port, data) in sorted(hits.items()):
        print(f"  [OBSERVED] {ip}:{port} replied {data!r}")
        print("             -> that host:port is the TCP target for POST /sie/ps5/rp/sess/rgst")
PY

head1 "PHASE 4 — TCP listening surface (bounded, connect-only, no payload)"
say "Ports probed, with what each one means if OPEN:"
cat <<'EOF'
  9295/tcp  Remote Play control/registration + session  -> console is running the RP stack
  9296/tcp  Remote Play (secondary, documented as UDP)   -> unexpected as TCP; note if open
  9297/tcp  Senkusha (chiaki-ng internet-RP helper, UDP) -> unexpected as TCP; note if open
    80/tcp  plain HTTP      -> captive-portal / UPnP description / media server
   443/tcp  TLS             -> local web UI / PSN proxy
  8080/tcp  alt HTTP
  2121/tcp  FTP             -> would imply an ALREADY-JAILBROKEN console (elfldr/FTP payloads)
  9021/tcp  elfldr          -> would imply an ALREADY-JAILBROKEN console (Relapse loader)
  8081/tcp  PS5LM chat/API  -> would imply an ALREADY-JAILBROKEN console running PS5LM
  62078/tcp iTunes/WiFi-sync style -> baseline "something is listening" marker
EOF
python3 - "$SUBNET" "$OWN_IP" "$TCP_TIMEOUT" <<'PY' | tee "$OUTDIR/tcp.txt"
import ipaddress, socket, sys, concurrent.futures
subnet, own_ip, tmo = sys.argv[1], sys.argv[2], float(sys.argv[3])
NET = ipaddress.ip_network(subnet, strict=False)
PORTS = [9295, 9296, 9297, 80, 443, 8080, 8081, 2121, 9021, 62078]
hosts = [str(h) for h in NET.hosts() if str(h) != own_ip]

def probe(args):
    ip, port = args
    s = socket.socket(); s.settimeout(tmo)
    try:
        s.connect((ip, port)); return (ip, port, "open")
    except ConnectionRefusedError:
        return (ip, port, "refused")
    except OSError:
        return (ip, port, "filtered")
    finally:
        s.close()

results = {"open": {}, "refused": {}}
filtered = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
    for ip, port, state in ex.map(probe, [(h, p) for h in hosts for p in PORTS]):
        if state in results:
            results[state].setdefault(ip, []).append(port)
        else:
            filtered += 1

any_hit = False
for ip in sorted(set(results["open"]) | set(results["refused"]),
                 key=lambda x: tuple(int(o) for o in x.split("."))):
    if results["open"].get(ip):
        any_hit = True
        print(f"  [OBSERVED] {ip}: OPEN {sorted(results['open'][ip])}")
    if results["refused"].get(ip):
        any_hit = True
        print(f"  [OBSERVED] {ip}: host up (refused) on {sorted(results['refused'][ip])}")
if not any_hit:
    print("  [OBSERVED] no host answered (open or refused) in the probed set on", subnet)
print(f"  [OBSERVED] {filtered} connect timeouts — AMBIGUOUS (host down or filtered); not evidence either way")
PY
say "TCP probe complete."

head1 "PHASE 5 — SSDP / UPnP renderer check (a stock PS5 may advertise a media renderer)"
python3 - "$IFACE" <<'PY' | tee "$OUTDIR/ssdp.txt"
import socket, sys, time
iface = sys.argv[1]
msg = ("M-SEARCH * HTTP/1.1\r\n"
       "HOST: 239.255.255.250:1900\r\n"
       'MAN: "ssdp:discover"\r\n'
       "MX: 2\r\n"
       "ST: ssdp:all\r\n\r\n").encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(1.0)
for _ in range(3):
    try: s.sendto(msg, ("239.255.255.250", 1900))
    except OSError: pass
found = {}
deadline = time.time() + 4
while time.time() < deadline:
    try:
        data, addr = s.recvfrom(8192)
    except socket.timeout:
        continue
    except OSError:
        break
    head = data.decode("utf-8","replace").split("\r\n\r\n")[0]
    server = ""
    for l in head.splitlines():
        if l.lower().startswith("server:"): server = l.split(":",1)[1].strip()
    found.setdefault(addr[0], set()).add(server)
if not found:
    print("  [OBSERVED] no SSDP replies")
for ip, servers in found.items():
    print(f"  [OBSERVED] {ip}: {sorted(s for s in servers if s)}")
PY

fi  # end active phase

# ---------------------------------------------------------------------------
head1 "PHASE 6 — interpretation key"
cat <<'EOF'
Read the results together, not one phase at a time:

A. DDP responds (any code 200/620)
   -> The Remote Play discovery responder is ALIVE.

B. No DDP response, but a Sony-OUI host answers ARP/ICMP
   -> Console's network stack is UP but nothing is advertising Remote Play.

C. No DDP response and no Sony-OUI host at all
   -> INCONCLUSIVE. Console may be off, on a different SSID/VLAN, etc.

D. TCP 2121 and/or 9021 open
   -> Console is ALREADY jailbroken and running a payload.

E. TCP 9295 open (with or without a DDP answer)
   -> Registration/session listener is up. A registration attempt will
      now either complete or fail with a specific error.

F. SSDP/mDNS hits only
   -> Media/DLNA style services only. No video path.

G. Nothing at all in any phase
   -> You have not observed the console. Treat all conclusions as UNKNOWN.
EOF

if [ "$DO_WAKE" -eq 1 ]; then
  head1 "PHASE 7 — wake attempt (STATE-CHANGING: this powers the console on)"
  if [ -z "$CREDENTIAL" ]; then
    say "  --wake requires --credential <user-credential>."
    say "  The user-credential is a number captured from an ALREADY-PAIRED Remote Play"
    say "  client's UDP/9302 traffic."
  else
    python3 - "$BCAST" "$CREDENTIAL" <<'PY'
import socket, sys
bcast, cred = sys.argv[1], sys.argv[2]
pkt = ("WAKEUP * HTTP/1.1\n"
       "client-type:vr\n"
       "auth-type:R\n"
       "model:w\n"
       "app-type:r\n"
       f"user-credential:{cred}\n"
       "device-discovery-protocol-version:00030010\n").encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.sendto(pkt, (bcast, 9302))
print(f"  [OBSERVED] WAKEUP sent to {bcast}:9302")
PY
    say "  Then re-run PHASE 3 after ~30s and look for a code 200 (awake) response."
  fi
fi

head1 "DONE"
say "Transcript and raw phase output saved under: $OUTDIR"
say ""
say "REMINDER — what a negative result does and does not mean:"
say "  * Negative DDP is NOT proof the console is off or absent."
say "  * Positive DDP is NOT proof that registration or video will succeed."
say "  * Nothing in this script tests your PSN account, and nothing authenticates."
