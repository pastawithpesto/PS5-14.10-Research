# Port 41800 on <PS5_IP> (PS5, LAN <PS5_SUBNET>) — GLM probe audit

- **Date of probe session:** 2026-10-14 20:09:58 – 20:10:30 CDT
- **Raw log:** `port41800-probes.log` (every exchange, raw bytes + timing)
- **Probe script:** `probe41800.py`
- **Authorization:** user-owned console, user-owned LAN; bounded plan followed exactly: 13 requests total (budget ~40), one connection at a time, 3 s timeouts, 2 s between probes, no concurrency from this session, no fuzzing beyond the fixed lists, no exploit payloads.
- **Stop conditions:** never triggered — no 4xx/5xx storms (zero HTTP responses received today), DDP answered identically before and after.

---

## OBSERVED (direct measurements)

### 1. Responder identity chain (all three agree on the same device)

| Layer | Evidence | Source |
|---|---|---|
| ARP | `<PS5_IP> dev <iface> lladdr <PS5_MAC> REACHABLE` (log line 186) | `ip neigh`, post-session |
| OUI | Sony OUI registered to **Sony Interactive Entertainment Inc.** (MA-L) | maclookup.app |
| DDP | UDP 9302 SRCH → `HTTP/1.1 200 Ok\nhost-id:<PS5_HOST_ID>\nhost-type:PS5\nhost-name:PS5-277\nhost-request-port:997\ndevice-discovery-protocol-version:00030010\nsystem-version:10400007` — identical before (log lines 12–15) and after (lines 178–181) the probe session | this session |

The DDP `host-id` is the ARP MAC without separators: the process answering on 41800's host is the PS5 itself.

### 2. Probe matrix — 13/13 identical result: connect OK → immediate FIN, zero response bytes

Every probe: TCP connect succeeded (2.3–40.0 ms), `sendall` OK, then the **server closed the connection 1.9–5.3 ms after the send with 0 bytes returned**. No status line, no headers, no body, no 404, no 400.

| # | Probe | Result | Log lines |
|---|---|---|---|
| 1 | `OPTIONS /` (HTTP/1.1, Host, UA, Connection: close) | silent close, 0 bytes, FIN +3.2 ms | 18–27 |
| 2 | `HEAD /` | silent close, +3.3 ms | 30–39 |
| 3 | `POST /` empty body (`Content-Length: 0`) | silent close, +5.3 ms | 42–51 |
| 4 | `GET /index.html` | silent close, +2.8 ms | 54–63 |
| 5 | `GET /rp` | silent close, +2.4 ms | 66–75 |
| 6 | `GET /sie/` | silent close, +3.1 ms | 78–87 |
| 7 | `GET /sie/ps5/rp/sess/rgst` | silent close, +2.9 ms | 90–99 |
| 8 | `GET /nonexistent-path-xyz` | silent close, +1.9 ms | 102–111 |
| 9 | `GET /` + `User-Agent: RemotePlay` | silent close, +3.2 ms | 114–123 |
| 10 | `GET /` + `RP-Version: 1.0` | silent close, +2.3 ms | 126–135 |
| 11 | `GET /` + `Host: localhost` | silent close, +2.8 ms | 138–147 |
| 12 | `GET /` HTTP/1.0 (UA + Connection: close, no Host) | silent close, +3.8 ms | 150–159 |
| 13 | `GET / HTTP/1.0\r\n\r\n` (bare minimal, no Host) | silent close, +2.8 ms | 162–171 |

Header experiments changed nothing: RemotePlay UA, RP-Version, Host rewrite to `localhost`, HTTP/1.0, missing Host — all identical silence. There is no HTTP-visible verb, path, or header surface at all from a generic client.

### 3. Prior-session captures of the same port (same console, hours earlier, 2026-10-14 19:56–20:01 CDT)

From `ps5-port-surface-19216810019/ps5-device-capture.har`:

- **41800 `GET /` (plain HTTP/1.1):** status 0, headersSize 0, body 0 bytes — silent close (HAR lines 148–190). Consistent with today's 13/13.
- **41800 malformed TLS bytes:** `HTTP/1.1 500 Server Error`, headers **only** `Content-Length: 48` and `Connection: close`, body `Error 500: Server Error\nClient closed connection` (48 bytes); server wait 39 ms (vs ~5 ms for `GET /`) before responding (HAR lines 191–244). No `Server`, no `Date`, no `Content-Type` header anywhere.
- **9295 `GET /` and `GET /sie/ps5/rp/sess/rgst` (same console, Remote Play "Teleport"):** `403` with `Connection: close`, `Pragma: no-cache`, `Content-Length: 0`, `RP-Version: 1.0`, `RP-Application-Reason: 80108bff` (HAR lines 16–146). A *different*, richer dialect — 41800 does **not** share the RP header set.
- **41800 `GET /spConn?action=getInfo&version=2.10.0` (read-only, unauthenticated, sent 20:10:10 CDT by a parallel workstream, not this session):** `HTTP/1.1 200 OK`, `Content-Type: application/json`, `Content-Length: 477`, no `Server`/`Date`; body JSON `remoteName=PS5-277, deviceType=GAMECONSOLE, modelDisplayName=ps5, brandDisplayName=sony_tv, status=101, statusString=OK, spotifyError=0, version=2.7.1, availability=SYSTEM-UPD-REQ, accountReq=FREE, scope=umbrella-tv` (exact fields in `spotify-getinfo-20261015-011010-UTC/{finding.md,result.json}`). `remoteName=PS5-277` matches DDP `host-name:PS5-277` from this session (log line 13). Server closed after its reply (`read_status: peer_closed`).
- An independent same-day scan got a 0-byte reply to `GET /` on 41800 (`codex-current-scan-20261015-010738-UTC/sha256.json`: `http-41800.bin` = SHA-256 of the empty string).

### 4. Console state

DDP answer byte-identical pre/post (system-version `10400007`, host-request-port `997`); ARP stayed REACHABLE; no error storm of any kind. Console state unchanged by the session.

---

## INFERENCE (reasoning, clearly separated from measurement)

**Framework elimination from the exact response shape.** The 500 (`HTTP/1.1 500 Server Error` + only `Content-Length`/`Connection` + LF body `Error 500: Server Error\nClient closed connection`) and the 200 (`200 OK` + only `Content-Type`/`Content-Length`) rule out every mainstream general-purpose server:
- **Go net/http** — always emits `Date`, canonical reason `Internal Server Error`, sniffs `Content-Type`, answers `404 page not found`. No match.
- **Node.js http** — `Date`, standard default reasons. No match.
- **nginx / Apache / lighttpd / mongoose / civetweb / BusyBox httpd** — `Server:` header + HTML error pages. No match.
- **Python BaseHTTPServer** — `Server: BaseHTTP/… Python/…`, `Internal Server Error`. No match.
- The RFC 7231 `Date` header is absent on *every* response ever captured from this port; reason phrases are bespoke (`Server Error` instead of `Internal Server Error`), and error bodies are a `printf("Error %d: %s\n%s", code, reason, detail)`-style template. This is a **hand-rolled embedded C/C++ HTTP server**, which matches what the Spotify embedded SDK ships as its ZeroConf HTTP daemon.

**Behavioral model.** The daemon routes on exact protocol paths (`/spConn`, historically also `/spSetup`) and treats everything else as not-its-protocol: instant silent FIN (~2–4 ms, faster than any HTTP response it produces) on unknown paths, wrong verbs, HTTP/1.0, missing Host. TLS handshake bytes are *not* silently dropped — the server spends ~39 ms attempting to process them, then emits its error template where the third line (`Client closed connection`) reads like the low-level read condition it hit when the handshake/parse failed. So the 500 is not "HTTP validation failed" (no request was ever parsed); it is the embedded server reporting an I/O-level failure in its error template. Notably, this console's *other* Sony HTTP dialects are also minimal and nonconforming (DDP's `200 Ok` with lowercase k, log line 13; 9295's `RP-*` 403s) — minimal-HTTP is the house style here, and 41800's dialect is distinct from both.

**Identification.** Port 41800 on this PS5 is the **Spotify Connect ZeroConf API** exposed by the console's Spotify application. Convergent evidence: (a) direct observation on *this* console — unauthenticated `GET /spConn?action=getInfo` returned Spotify ZeroConf JSON whose `remoteName` equals the DDP host-name; (b) `deviceType: GAMECONSOLE`, `modelDisplayName: ps5`; (c) independent external corroboration that 41800 is the PlayStation Spotify Connect port: a TU Wien thesis recorded ports 9295/41800 with a Spotify Connect advertisement on 41800 for a PS4 Pro ([Stoeger 2023, pp. 72–73](https://repositum.tuwien.at/bitstream/20.500.12708/176654/1/Stoeger%20Michael%20Bernd%20-%202023%20-%202023%20-%20Scanning%20for%20IoT%20Devices%20Using%20a%20Mobile%20Android...pdf) — exact URL in `spotify-getinfo-20261015-011010-UTC/finding.md`), and [Shodan's mDNS documentation](https://datapedia.shodan.io/property/mdns.html) shows Spotify Connect examples with port 41800 and CPath `/spConn`; (d) a first web-search pass found 41800 in **no** Sony port documentation — it is not a system-service port. The silence-to-everything behavior is exactly how libspotify's embedded ZeroConf server treats non-protocol input.

---

## VERDICT (one paragraph)

TCP 41800 on <PS5_IP> is most plausibly (and, given the direct `/spConn` capture from this very console, effectively confirmed to be) the **Spotify Connect ZeroConf API of the PS5's Spotify app**: a tiny embedded C HTTP server that speaks the Spotify ZeroConf protocol (`getInfo`, and by protocol design `addUser`/pairing, on exact paths), answers its protocol routes with minimal-header responses (no Server/Date, peer-closed after reply), and closes silently — ~2–4 ms FIN, zero bytes — on every well-formed HTTP request outside its path set, with a bespoke `Error 500: Server Error\nClient closed connection` template reserved for failed reads. It is not a system-management, remote-play, debug, or upload surface; it is a companion-device pairing endpoint for Spotify, running under the user's own Spotify app on their own console.

**Unauthenticated write path: none demonstrated.** (1) Every write-shaped request this session — `POST /` with `Content-Length: 0` (log lines 42–51) and `OPTIONS /` (lines 18–27) — was answered with silence and immediate close: no 2xx, no `Allow`, no 100-continue, nothing accepted. (2) The only response this port has *ever* produced to a valid request, on this console, is the read-only `getInfo` JSON — an unauthenticated **read/info-disclosure** (exposes deviceID/activeUser/publicKey-class fields per `result.json`), not a write. (3) The ZeroConf protocol does define a write (`POST /spConn?action=addUser`, i.e., pairing a Spotify account); it was deliberately **not** attempted here (it would mutate the user's Spotify app state), and the returned `availability=SYSTEM-UPD-REQ` / `accountReq=FREE` indicate the app was not in an open pairing-offering state — so no unauthenticated write exists in evidence, and none should be assumed without testing `addUser`, which is out of scope for a passive audit. Nothing this session changed console state (DDP identical pre/post, log lines 12–15 vs 178–181).

## Caveats

- Probe 9's script appended the baseline `User-Agent` after `User-Agent: RemotePlay` (duplicate UA header); the raw bytes are logged verbatim (log line 117) and the result (silence) is unaffected.
- Probe 12 ended up as "HTTP/1.0 without Host (with UA)"; probe 13 is "HTTP/1.0 bare". Both no-Host permutations were covered; all returned identical silence.
- A sibling workstream sent one read-only `getInfo` request to 41800 at 20:10:10 CDT, inside this session's window. This session itself did zero concurrent probing; the console answered both workstreams normally.
- Firmware `system-version:10400007` (log line 13) — read as a 10.40-series firmware (inference from Sony version encoding).
