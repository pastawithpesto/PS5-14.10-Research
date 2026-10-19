# Media-decoder crash battery — plan (PS5 14.10, headless, USB-fed)

**Status:** `[PLAN]` — desk work only. No console was contacted, no network scan was run, no
sample was downloaded, no file was generated, no existing file was modified. All URLs below are
*citations to be fetched/verified in the execution phase*, not fetched here.
**Date:** 2026-10-18. **Target:** the user's own retail PS5 on firmware 14.10, headless (dead HDMI
output), operated via a chiaki-ng Remote Play stream + USB-HID keyboard-emulation navigation
scripts.
**Tag legend:** `[OBS]` = observation with a local receipt (file/path quoted) · `[INF]` = inference
(explicitly labelled) · `[UNK]` = unknown / bounded absence (state what was/will be checked) ·
`[PLAN]` = decision or convention defined by this document.

---

## 0. Objective and the two questions the battery must answer

**Objective:** localize crash-prone native media decoders by feeding a bounded, provenance-tracked
corpus of crafted files from USB mass storage into the console's own media surfaces (photo viewer /
Media Gallery, video player, music / background-audio player), and produce an evidence-grade crash
map: *which file, which surface, what happened (app crash vs. reboot vs. hang), reproducible or not.*

Two questions, in priority order:

- **Q-A (recon):** *Which* media surfaces consume files from a USB drive at all, and which formats
  does each surface accept on 14.10? This answers the whole-battery go/no-go.
- **Q-B (battery):** For each format family, which specific input files crash the consuming decoder,
  and is the crash deterministic?

**Expected failure mode:** application crash returning to the PS5 home screen; worst credible case a
console reboot. **Discipline:** crash-only (never aim past a crash — no exploitation, no persistence,
no console-storage writes), bounded (fixed file counts, fixed session lengths, hard stop conditions),
no bricks (nothing in this plan touches firmware, Safe Mode, or console storage).

Non-goals, explicitly: no fuzzing-at-scale, no exploit development, no firmware/USB-PUP experiments
(that lane — `PS5/UPDATE/PS5UPDATE.PUP` — stays separate), no use of the WebKit beacon harness during
battery sessions (separate lane; keep evidence streams unconfounded).

---

## 1. Ground rules (zero-brick policy)

1. **Read-only console storage.** Battery files are played *from the USB drive*. Every path that
   would write to console storage (import/copy to console, "set as wallpaper", screenshots, uploads)
   is out of scope and is never exercised. `[PLAN]`
2. **One file open at a time**, bracketed by logged OPEN/CLOSE events (§6, §7). No auto-advance,
   no playlists.
3. **No Safe Mode.** Power-button discipline: normal power-off = hold ~3 s (Sony's documented
   "turn off" timing `[OBS]` dossier §Q1e); Safe Mode entry is a *second beep ≈ 7 s* hold
   (`[OBS]` same). Recovery procedures must stay well under that window and never navigate Safe Mode.
4. **No firmware actions.** Never accept a system-software update prompt; never insert a
   `PS5/UPDATE/` PUP drive during battery sessions.
5. **No repair/format prompts accepted.** If the console offers to "repair" or "format" the USB
   drive, decline, power off, and move the drive to the host for read-only inspection.
6. **Bounded sessions.** Fixed per-session file caps and wall-clock caps (§9); a human is present
   for drive swaps and power-button work for the whole session.
7. **Stop conditions are pre-committed** (§9). The operator does not negotiate with them mid-session.
8. **Evidence discipline** (§10): raw logs outrank summaries; every crash claim needs a receipt and
   a second-pass confirmation before it is called settled `[OBS]`.

---

## 2. Existing infrastructure reused (receipts)

All reused as-is; new tooling is created **new files** under `media-battery/` — existing scripts are
never edited in place (house rule from `14.10-bid/operator-instructions-claude.md` §1.8).

| Asset (path) | What it gives us | Use in battery |
|---|---|---|
| `14.10-bid/console-watch.sh` | State-change watcher: pings the two documented console addresses (WiFi + direct link), probes TCP 9295/41800, logs only transitions to `console-watch.log` `[OBS]` | **Reboot detection.** A down→up transition of ICMP + RP-stack TCP + (below) DDP = reboot candidate `[PLAN]` |
| `ps5-wake` (`ps5-wake.c` + `ps5-wake-README.md`) | DDP (UDP 9302) probe: read-only console status/identity; wake with credential `[OBS]` | Liveness + **awake/rest discrimination**; DDP silence concurrent with ICMP loss = reboot, not app crash `[PLAN]` |
| `14.10-bid/verdict-watch.sh` | Pattern: a 20 s loop parses a log and auto-writes a verdict doc + change-only log line `[OBS]` | Pattern for `mb-watch.sh` → auto-`MATRIX.md` from the session log `[PLAN]` |
| `14.10-bid/ack-watchdog.sh` | Pattern: heartbeat files (`ack-*.heartbeat`) + mtime-age scan into `ack-status.log` `[OBS]` | Pattern for session-tool heartbeats (`mb-<session>.heartbeat`) so a hung prep/watcher process is visible `[PLAN]` |
| `14.10-bid/ds-watchdog.sh` | Pattern: poll process liveness → `notify-send` desktop alert (Omarchy) `[OBS]` | Pattern: alert the operator on session-start/-end/crash events instead of watching terminals `[PLAN]` |
| `luckma-hid_navigate.py`, `luckma-nav_sequence.py` (`/ps5-lan-research/`) | USB-HID keyboard emulation over `/dev/hidg0`; key-code table; timed SEQUENCE playback; per-key logging to `/tmp/nav_log.txt` `[OBS]` | **Navigation engine.** Reuse `send_key`; replace the fixed SEQUENCE with a step log that records each keypress with UTC + intended target `[PLAN]` |
| chiaki-ng + `postjb-tools/write-chiaki-host.py` | A registered chiaki host config can be written/held locally `[OBS]` | **Visual channel.** Keep a chiaki stream up for every session; reconnect after reboots `[PLAN]` |
| `14.10-bid/e2e-beacon-test.sh` + GO-LIVENESS.md §"Validación end-to-end del harness SIN consola" | House pattern: validate the full tooling chain against a local stand-in *before* touching the console `[OBS]` | **P0 dry-run pattern** for the battery tooling (§3) `[PLAN]` |
| `device-audit-20261014.md`, `README-MISSION.md`, `GO-LIVENESS.md` | Device facts: two console addresses, RFID of the setup; identity dispute open (`10400007` control-plane record vs. `14.10` WebView UA — *"DISPUTED en vivo"*) `[OBS]` | Pre-flight item: record identity receipts at the first session; **do not build conclusions on the disputed field until the harness/receipts resolve it** `[PLAN]` |

**Not reused:** the DNS/HTTPS beacon harness, `host.py`, exploit/loader chain, port-41800 Spotify
probes, `ps5upload` (post-jailbreak only). Battery stays on the USB + UI + chiaki path.

---

## 3. Phase P0 — offline pre-flight (no console contact)

Goal: everything that can be validated without the console, validated without the console.

1. **Drive layout + manifests.** Build the drive-preparation script (`media-battery/tools/mkdrive.sh`
   + `mkmanifest.sh`) that populates a drive from a corpus manifest and writes `manifest.sha256` +
   `provenance.tsv` (source URL, CVE/ticket id where applicable, mutation seed if any, intended
   family/batch). Two layout variants prepared: **A** — files directly under one root folder per
   batch (`/MDB/<fam>-<batch>/`); **B** — a `PS5/`-style sibling folder alongside nothing else is
   *not* used; if recon shows the viewer only lists files in a particular location, variant A is
   adjusted from recon receipts `[PLAN]`.
2. **Log schema + summarizer dry-run.** Fixed NDJSON schema (§7); feed synthetic logs (including a
   simulated `OPEN` without `CLOSE`, a simulated reboot transition) through the summarizer and
   confirm `MATRIX.md` classifies each case correctly — the `e2e-beacon-test.sh` pattern `[OBS]`.
3. **Watcher dry-run.** `mb-watch.sh` against a local stand-in address, and against real absence of
   any device, must log exactly the intended state transitions without spamming.
4. **Chiaki dry checks.** Locally verify: current chiaki-ng binary connects to a registered host;
   whether this build can record the stream to a file (`chiaki-ng --help` / docs check — recording
   or window screenshots either satisfies the frame-receipt requirement) `[UNK]` until checked.
5. **HID dry-run.** Send a single benign key (e.g., `DOWN`) and a `PAGE_UP` to confirm `/dev/hidg0`
   plumbing and the log line format — with the console *off or absent*, the write either errors or
   is queued; do not leave the gadget in a pressed state (always send the zero-byte release
   report, as `send_key()` does `[OBS]`).
6. **Corpus is NOT assembled in P0 of this document.** Corpus assembly (fetching the sources listed
   in §5, mutating seeds, checksumming) is its own execution task with its own review gate.

**P0 exit criterion:** dry-runs PASS; drive script produces byte-identical manifests on re-run.

---

## 4. Phase R — recon: what does 14.10 actually consume from USB?

Run with a **minimal non-crashing baseline drive**: ≤14 files, all valid, all tiny, one per family
(`jpg png gif webp bmp tif mp4 hevc mkv/webm mp3 aac flac wav`) plus 1 duplicate control moved to
end-of-list. Baseline files are the *most vanilla* legal forms (e.g., 1–8 MP JPEG/PNG photo, 2–5 s
H.264 MP4, 2–5 s MP3/AAC/FLAC/WAV, 1-page TIFF, 1-frame GIF/WebP). One batch, one session, human at
the console.

**R1 — Drive recognition.**
- Insert drive. Record: any on-screen toast/prompt, whether an app auto-opens, and the exact UI text
  (chiaki frames as receipts). `[OBS]`
- Test FAT32 first (PUP precedent shows FAT32/exFAT drives are readable at least by system software
  `[OBS]` dossier Q1a); if files are not listed, retry with exFAT variant before concluding. `[PLAN]`

**R2 — Surface mapping.** For each family file, attempt the plausible path and record which app
handles it:
- Photo files → **Media Gallery** photo viewer (and note: is there a USB source picker? thumbnails
  or file list? does entering a folder decode all thumbnails at once? — this last point changes the
  crash-attribution protocol, §7).
- Video files → whatever app the console opens (video player / Media Gallery playback / "no
  compatible app").
- Audio files → music playback; check both "music player" surface and any Quick Menu background-music
  entry; note whether playback continues in the background (it changes the CLOSE step, §6).

**R3 — HID macro capture.** For each surface, record the exact minimal key sequence
(open → next item → open file → back) and store it as a named macro in the nav script
(`mac-photo-open`, `mac-video-open`, `mac-music-stop`, `mac-home`). Every macro run logs per-key
UTC lines (§7). `[OBS]` receipts = chiaki frames + key log.

**R4 — Go/no-go per family.** Output `recon-map.md` with a table: family × surface × accepted ✓/✗ ×
navigation macro × notes. Families with no consumption path are marked `N-A` and stay out of the
battery (no forced paths; e.g., if 14.10 will not list TIFF at all, TIFF is a recon result, not a
failure of the battery).

**R5 — Ambiguity checks.** Confirm with tiny two-file tests:
- Does the viewer decode thumbnails for the whole folder on entry? (To detect: a folder with one
  deliberately broken file among valid ones would show a placeholder thumb — do this only in the
  battery phase, not with the clean baseline. In recon, just *observe* thumbnail behavior of valid
  files.)
- Does "back" from a video/audio return to home or to the list? Is audio stopped by leaving the app?
- Does removing the drive mid-list cause a warning? (Do not test removal mid-playback.)

**R exit criterion:** `recon-map.md` complete; at least one consumable family; macros captured.

---

## 5. Corpus design — sources and per-family plan

Design rules `[PLAN]`:
- **Provenance-tracked**: every corpus file carries a row in `provenance.tsv` (origin URL, CVE/ticket
  or corpus id, mutation seed if mutated). No anonymous files.
- **Four strata per family**: (a) valid seeds, (b) legal-but-nasty structural edge cases, (c)
  known-CVE/regression-derived samples, (d) single-pass mutations of seeds (bounded count).
  No stacking of mutations; each mutated file = one artifact of one recorded seed + one recorded
  mutator seed.
- **Hard cap 64 files/family**; batch cap 16 (§6).
- **Verification before deployment**: every file is parsed by a host-side reference decoder
  (ffmpeg / Pillow / libtiff tools / flac / sox as applicable) and the parse result recorded —
  this distinguishes "decoder crash" from "file was never parseable" and is a baseline receipt.
- Sources marked `[verify]` below have URLs that must be confirmed reachable at corpus-assembly
  time (none were fetched in this task).

### 5.1 Photo families

| Family | Planned sources | Stratum focus | Notes |
|---|---|---|---|
| **JPEG** | libjpeg-turbo `testimages/` (github.com/libjpeg-turbo/libjpeg-turbo, dir `testimages`) `[verify]`; JPEG Club test images (jpegclub.org) `[verify]`; Pillow tests `Tests/images` incl. regression files (github.com/python-pillow/Pillow) | grayscale/CMYK/progressive; EXIF orientation + embedded thumbnail; oversized dims; truncation after EOI; restart-interval edges | `CVE-2020-35538` family of decoder NULLs surfaced via libjpeg-turbo regressions `[verify id]` |
| **PNG** | **PngSuite** (schaik.com/pngsuite/) — canonical valid + error files; libpng repo regressions (github.com/pnggroup/libpng) | all color types/bit depths; interlace; tRNS/PLTE variants; chunk-order oddities; IDAT split; zero-length chunks; APNG test suite (philip.html5.org/tests/apng) only if viewer shows animation `[verify]` | `CVE-2018-13785` (png_check_chunk_length) regression inputs via libpng `[verify id]` |
| **GIF** | giflib `pic/` + tests (sourceforge.net/projects/giflib) `[verify]`; Pillow GIF regression images | LZW width-change edges; interlace; transparency; local palettes; long frame counts; extension blocks | `CVE-2018-11490`-class decompression edge `[verify id]`; prefer upstream regression files |
| **WebP** | **libwebp-test-data** (github.com/webmproject/libwebp-test-data) — valid corpus incl. lossless/alpha/animation; libwebp regression files for `CVE-2023-4863` (BLASTPASS; fixed in libwebp 1.3.2) `[OBS]` public CVE; sample = OSS-Fuzz minimized testcase `[verify id]` | VP8/VP8L/VP8X; alpha; ANIM/ANMF; odd dims; ICC/XMP chunks | High-value family: real-world exploited bug class in exactly this decoder |
| **BMP** | **bmptest** (github.com/jsummers/bmptest) — large valid+malformed suite `[verify]`; file(1) tests (github.com/file/file, `tests/`) | RLE4/RLE8; bitfields; 16/32bpp; negative height (top-down); OS/2 headers; odd row padding; palette edges | bmptest's malformed half is the intended crash material; cite James Summers' suite |
| **TIFF** | libtiff `test/images` (gitlab.com/libtiff/libtiff) — valid + CVE regression files + BigTIFF `[verify]`; Pillow broken-TIFF files | tiled/striped; LZW/PackBits/Deflate/old-JPEG compression; multi-IFD chains; deep/huge tag counts; sample formats | `CVE-2016-5321`-era regression files are checked into libtiff `test/images` `[verify names]` |

### 5.2 Video families

| Family | Planned sources | Stratum focus | Notes |
|---|---|---|---|
| **MP4/AVC** | FFmpeg **FATE** suite (fate-suite.ffmpeg.org; mirrors at samples.ffmpeg.org) — H.264 samples + conformance set `[verify]`; Bento4 `Test/` content (github.com/axiomatic-systems/Bento4); GPAC test suite (github.com/gpac/gpac-test-suite) `[verify]`; ITU-T/JVT conformance streams `[UNK url]` | fMP4 segments; moov placement; edit lists; rotation; big sample tables; MBAFF/interlace; cropping; multi-track; avcC SPS/PPS edge encodings; truncation mid-sample | FFmpeg trac tickets + OSS-Fuzz testcases for mov/h264 = canonical CVE-derived samples `[verify per-ticket]` |
| **HEVC** | FATE HEVC samples; Bento4/GPAC content; JCT-VC/ITU conformance `[UNK url]` | Main/Main10; 4:4:4/monochrome; tiles/WPP; dependent slices; small GOPs; hvcC variants; 10-bit | Container-level edges shared with MP4 row |
| **WebM/MKV** | **ietf-wg-cellar/matroska-test-files** (github.com/ietf-wg-cellar/matroska-test-files; fallback: Matroska-Org/matroska-test-files) — *purpose-built valid + invalid sets* `[verify]`; webmproject VP8 test vectors `[verify]`; FATE mkv/webm | EBML unknown-size; void/CRC; lacing modes; BlockGroup vs SimpleBlock; huge clusters; attachments/subtitles | The invalid set is literally designed for demuxer robustness testing |

### 5.3 Audio families

| Family | Planned sources | Stratum focus | Notes |
|---|---|---|---|
| **MP3** | FATE MP3 samples; mpg123 site test section (mpg123.de) `[verify]`; MAD resource streams (underbit.com/resources/mpeg) `[verify]` | ID3v2 extremes (unsync, huge tags); VBR headers; free-format bitrate; bit-reservoir edges; truncation; mono/joint-stereo | Decoder lineage differs from images; report separately |
| **AAC** | FATE AAC samples; MPEG-4 AAC conformance (ISO/IEC 14496-4 distribution — availability `[UNK]`, likely paywalled) | ADTS framing edges; SBR/HE-AAC; channel configs; ASC variants; priming/truncation | If conformance set is not freely available, rely on FATE + OSS-Fuzz samples |
| **FLAC** | **ietf-wg-cellar/flac-test-files** (github.com/ietf-wg-cellar/flac-test-files) — valid + deliberate invalid files; xiph/flac repo tests (github.com/xiph/flac) | subset/non-subset; 24-bit/high rates; wasted bits; seektable; frame-header edges; zero-length frames | One of the few families whose canonical corpus *includes* spec-designed invalid files |
| **WAV** | libsndfile tests (github.com/libsndfile/libsndfile, `tests/`) `[verify]`; file(1) tests; FATE WAV samples | chunk order/unknown chunks; WAVE_FORMAT_EXTENSIBLE; 8/16/24/32-bit; data-size mismatch; multiple data chunks; ADPCM variants | libsndfile tests include CVE regression files `[verify]` |

### 5.4 Mutation tooling (execution phase only — not run now)

- **radamsa** (gitlab.com/akihe/radamsa) — generic, seed-reproducible; record `--seed` per output.
- **zzuf** (caca.zoy.org/wiki/zzuf) — byte-flip with recorded rate/seed.
- **AFL++** (github.com/AFLplusplus/AFLplusplus) — only for *coverage-guided corpus generation
  against a local reference build* of an analogous decoder; contributes seeds, not crash evidence
  about the PS5. `[PLAN]`
- Budget: ≤32 mutated files per family, each from a recorded seed at a low mutation setting;
  mutation of CVE-derived samples is not done twice-over.

### 5.5 Corpus priority (decision gates)

- **Phase A — photos** (jpg, png first; then gif, webp, bmp, tif). Simplest UI path, fastest per-file
  cycle, highest decoder-crash prior. Gate **G1**: Phase A crash map reviewed before Phase B starts.
- **Phase B — video** (mp4/avc, hevc, mkv/webm). Longer dwells, heavier decoder state; gate **G2**
  before Phase C.
- **Phase C — audio** (mp3, aac, flac, wav). `[PLAN]`
- Order within a phase is by source availability and recon acceptance; skipped families are recorded
  as recon results.

---

## 6. Probe protocol

### 6.1 Session anatomy (one family per session)

1. **Pre-session (host):** fsck/verify drive read-only on host; regenerate `manifest.sha256`; confirm
   it matches the recorded manifest; start `mb-watch.sh`; start chiaki stream; confirm home screen
   visible; start session log with header line (session id, drive id, corpus batch, tooling versions).
2. **Clean baseline check:** with the battery drive present, if a separate baseline drive exists use
   it; otherwise open the designated `BASE/` folder and smoke-test 3 files (one photo, one video,
   one audio — whichever the recon map says are consumable). Expected: no crash. Any anomaly here →
   **halt session** (§9).
3. **Batch loop** (≤16 files, one at a time, in filename order):
   - log `OPEN f<NN> <fid> <utc>`; run the recon macro to the file; dwell (§6.2); log `CLOSE f<NN>
     OK <utc>`; return to list/home; inter-file gap 5–10 s.
   - Any anomaly → log `ANOMALY ...` and follow §9 immediately.
4. **Post-session (host):** stop watchers; append session footer; copy chiaki receipts; write/refresh
   `MATRIX.md`; update `current-session.txt` (one-line pointer, mirroring the `current.txt` probe
   convention).

### 6.2 Dwell times

- Photos: open, wait for full render (≤10 s), verify rendered (chiaki), CLOSE.
- Video: play 20–30 s, then explicit stop/back; if the player loops by itself, dwell is still 20–30 s
  and the stop is forced by macro.
- Audio: play 20–30 s, explicit stop; confirm playback actually stopped before next OPEN (background
  audio that keeps playing across the UI is its own acceptance ambiguity — resolved in recon R5).
- Every dwell uses a timer in the HID script so OPEN→CLOSE windows are machine-timed and logged.

### 6.3 Crash attribution and bisection

- **Unambiguous case:** an `OPEN` with no matching `CLOSE OK` in the same session, with the console
  showing home/crash afterwards → the crashed file is the `OPEN`ed one. Single-pass = *provisional*.
- **Grid-decode ambiguity:** if the crash happens *while a folder's thumbnails/list renders* (no
  single file open), the suspect set = the folder's ≤16 files. Bisect by **folder halves**
  (8/8 → 4/4 → 2/2 → 1/1) across sessions: each half is a new batch on the drive, with the clean
  baseline smoke before each re-entry. `[PLAN]`
- **Confirmation pass:** every provisional crash is re-tested alone (single file in a folder, clean
  baseline smoke first) in a later session. Crash again → `CONFIRMED [OBS]`; no crash → downgrade to
  `UNCONFIRMED [UNK]` (possible state dependence). Cap: 2 confirmation attempts per file, then stop
  and record.
- Bisection bounds: ≤5 rounds, ≤8 file-opens per round. If bisection stalls (both halves survive),
  the crash was state-dependent — record as such.

### 6.4 Bounded counts (hard)

| Bound | Value |
|---|---|
| Files per batch/session | ≤16 |
| Opens per session | ≤32 (a batch plus a small re-run), wall-clock ≤90 min |
| Sessions per day | ≤2, one family per session |
| Confirmation attempts per suspect file | ≤2 |
| Corpus cap per family | ≤64 files (§5) |

---

## 7. Crash↔file mapping: naming and logging convention

**Session id:** `<fam>-b<NN>-<yyyyMMdd-HHmmss>` (e.g., `jpg-b01-20261020-153000`).

**File naming (on the drive):** `f<NN>_<fam>_<origin>_<slug>.<ext>`
- `f<NN>` = 2-digit ordered index (f00..f99); fixed-width so viewer sort order = log order.
- `fam` ∈ {jpg,png,gif,webp,bmp,tif,mp4,hevc,mkv,webm,mp3,aac,flac,wav}; `origin` ∈
  {seed,cve,mut,base}; `slug` = short ascii; lowercase, no spaces (FAT-safe).
- Example: `f07_jpg_cve_cve2018-13785.png` `[PLAN]`.

**Embedded marker (where the container allows):** `MDB:<fid>|<sha256-prefix>` inserted at
generation time into: PNG tEXt/Comment · JPEG COM · GIF Comment Extension · WebP EXIF/XMP · BMP/RIFF
INFO · TIFF ImageDescription · MP4 `udta`/©cmt (or a `free` box payload) · MKV Tags · MP3 ID3v2 COMM ·
FLAC Vorbis comment · WAV LIST/INFO. If a mutated file cannot carry the marker, the position order +
manifest hash is the identity. `[PLAN]`

**Session log (NDJSON, append-flush):** each line `{t, ev, fid, seq, src, note}`, `ev` ∈
`OPEN|CLOSE|NAV|DDP|PING|ANOMALY|REBOOT|NOTE`. NAV lines carry intended target fid + key sent + UTC.
This makes the crash bracket unambiguous: last `OPEN` without `CLOSE OK`; NAV count maps viewer
position → fid through the manifest. `[PLAN]`

**Receipts naming:** `<session>_<fid>_<phase>.png` for chiaki frames (open/rendered/closed), plus the
raw logs (`mb-watch.log` excerpt, key log, DDP probe transcript). `[PLAN]`

---

## 8. Observation instrumentation without HDMI

**Channels:**

1. **Video (chiaki-ng stream):** the session's primary eyes. Screenshots (host-side capture of the
   chiaki window) at OPEN/rendered/CLOSE, or stream recording if the installed build supports it
   `[UNK]` until checked in P0. A frozen stream + live console = *hang*; dropped stream + dead
   console = *reboot*; dropped stream + live console = *transport issue* (distinguish via watcher).
2. **Liveness / reboot detection (wire):** `console-watch.sh`-style watcher (new copy, extended)
   polling: ICMP to the known console addresses → TCP 9295/41800 → DDP UDP 9302 status via `ps5-wake
   -P`. A simultaneous down+up with a multi-second gap, matching chiaki's disconnect gap = reboot
   `[OBS]`. All probes are targeted at the console's known addresses only — **no scanning** `[PLAN]`.
3. **HID key log:** every keypress with UTC + intended fid (from the reused `send_key` plumbing
   `[OBS]`).
4. **Heartbeats / watchdogs:** `mb-<session>.heartbeat` touched by the session driver; watcher logs
   staleness (ack-watchdog pattern `[OBS]`); desktop notifications on session events
   (ds-watchdog pattern `[OBS]`).
5. **Auto-summarizer:** `mb-watch.sh` (verdict-watch pattern `[OBS]`) deriving, per fid, one of
   `NO-CRASH / CRASH-APP / CRASH-REBOOT / HANG / NOT-CONSUMED / INCONCLUSIVE` from the raw log only —
   no manual interpretation required; every classification cites the raw lines it consumed.

**Pre-session checklist (all must be green):** chiaki stream up & stable; watcher logging;
heartbeats fresh; drive manifest verified; baseline smoke PASS; console identity note recorded
(identity dispute `[OBS]` README-MISSION — record what this session observed, resolve nothing by
assumption).

---

## 9. Stop conditions and recovery runbook

### Stop conditions (pre-committed)

| # | Trigger | Action |
|---|---|---|
| S1 | Baseline smoke crashes/reboots | **Halt whole battery.** Platform is not stable; nothing about the corpus is measurable. |
| S2 | Reboot during a family session | End the session (log `REBOOT`). Mandatory cool-down ≥10 min + baseline re-check at the next session start. |
| S3 | **≥2 reboots within one family** (across sessions) | **Halt that family; reassess with the user before any further batch.** |
| S4 | ≥3 reboots total across the battery | Halt everything; reassess approach (drive? port? console state?) before resuming. |
| S5 | 3 consecutive hangs (no crash) in one family | Halt family (viewer may be silently stuck on one file). |
| S6 | Any repair/format/update prompt, any Safe Mode screen | Decline, power off, end session; change nothing until reviewed. |
| S7 | Chiaki observation degraded (lag/frames lost) for >1 file | Pause until it is restored — observation integrity is a precondition, not a nicety. |
| S8 | Any uncertainty about which file was open | Stop the batch; resolve by manifest + NAV log before proceeding. |

### Recovery runbook

- **App crash (stream alive, home visible):** wait 10 s; screenshot; log `ANOMALY`; the crashed file
  is bracketed by the OPEN/CLOSE rule; stop the batch; session continues only with host-side wrap-up.
- **Hang (screen frozen, ICMP+DDP alive):** send BACK/PS-equivalent HID key once, wait 30 s; if still
  frozen, wait 2 min, then power-off: hold power ~3 s (well under the ~7 s Safe Mode second-beep
  window `[OBS]` dossier Q1e); wait 10 s; power on (short press); confirm home via chiaki; S5 rules.
- **Reboot (screen gone, ICMP+DDP down):** wait up to 5 min; if DDP returns and chiaki reconnects →
  confirm home, log `REBOOT` with both timestamps; S2 applies. If not back in 5 min: one power-cycle
  (§above), then if still dead → S4 halt, physical check by the operator (LED/beeps), do not loop.
- **Drive issues:** never accept on-console repair/format; power off before removing the drive after
  any anomaly; inspect the drive read-only on the host; keep a spare FAT32 drive so a corrupted drive
  does not block the next session.
- **Record after every unusual event:** crash card (`§10`) with the raw bracket lines + chiaki frame
  names; nothing verbal — if it is not in a log/receipt, it did not happen.

---

## 10. Evidence standard and results layout

**Paths (append-only history, house rule `[OBS]` AGENTS.md §4):**

```
media-battery/
  MATRIX.md                    # auto-generated family × fid × verdict, cites raw lines
  current-session.txt          # one-line pointer, current.txt convention
  CHANGELOG.md                 # corrections go here as new dated sections
  corpus/<fam>/<batch>/        # staged files + manifest.sha256 + provenance.tsv
  sessions/<session-id>/
      session.log              # NDJSON (append-only)
      mb-watch.log             # state-change log excerpt for the session
      hid-keys.log
      receipts/                # chiaki frames, DDP transcripts, drive manifests
      wrap-up.md               # dated summary: [OBS]/[INF]/[UNK]
  cards/cc-<session>-f<NN>.md  # one crash card per suspect file
```

**Crash card skeleton:** file (fid, sha256, size, provenance + mutation seed), surface, expected vs.
observed, raw bracket lines quoted with line numbers, chiaki receipt names, reboot evidence (watch
window), reproducibility status (`CONFIRMED [OBS]` / `UNCONFIRMED [UNK]`), and top candidate decoder
classes as `[INF]` only.

**Tag rules:** `[OBS]` requires a path + line/quote; `[INF]` must say what it is inferred from;
`[UNK]` must state the bounded work that would resolve it. Raw logs outrank any summary — a
`MATRIX.md` line without supporting raw lines is downgraded to `[INF]` `[OBS]` operator-instructions
§1.6. Single-pass results are provisional; only second-pass reproductions are settled.

---

## 11. Open questions ([UNK] register)

1. Which USB media surfaces exist on 14.10 and which formats each consumes — resolved by R1–R4.
2. Whether chiaki-ng streams the native media surfaces (vs. only home/games) — resolved at R1; a
   fallback (host-side audio observation? [UNK]) may be needed if a surface is not streamed.
3. Whether the photo viewer decodes thumbnails for an entire folder on entry — resolved at R1/R5;
   decides bisection-by-folder (§6.3).
4. Whether FAT32 vs exFAT changes acceptance — resolved at R1 (variant B only if needed).
5. Console identity dispute (`10400007` control-plane record vs. `14.10` UA) `[OBS]` README-MISSION —
   record what the battery session observes; do not silently pick a side.
6. Exact per-file consumption behavior for each audio family (does "music" accept FLAC/WAV/AAC at
   all) — resolved at R2/R4.
7. Whether any crash family signature can be tied to a public library version later — out of scope
   here; noted so nobody assumes attribution during the battery.

---

## 12. Sources (to fetch/verify in the execution phase — none fetched here)

Test corpora: PngSuite (schaik.com/pngsuite) · libpng (github.com/pnggroup/libpng) · libjpeg-turbo
testimages (github.com/libjpeg-turbo/libjpeg-turbo) · JPEG Club (jpegclub.org) · Pillow tests
(github.com/python-pillow/Pillow) · giflib (sourceforge.net/projects/giflib) · libwebp-test-data
(github.com/webmproject/libwebp-test-data) · bmptest (github.com/jsummers/bmptest) · libtiff
(gitlab.com/libtiff/libtiff) · libavif tests (github.com/AOMediaCodec/libavif) `[optional]` ·
FFmpeg FATE (fate-suite.ffmpeg.org / samples.ffmpeg.org) · Bento4 (github.com/axiomatic-systems/Bento4) ·
GPAC test suite (github.com/gpac/gpac-test-suite) · matroska-test-files
(github.com/ietf-wg-cellar/matroska-test-files) · VP8 test vectors (github.com/webmproject) `[verify]` ·
flac-test-files (github.com/ietf-wg-cellar/flac-test-files) · xiph/flac (github.com/xiph/flac) ·
libsndfile (github.com/libsndfile/libsndfile) · file(1) tests (github.com/file/file).
CVE-derived sample sources: upstream regression files added by the fixing commits (canonical),
OSS-Fuzz public testcases + issue tracker (google.github.io/oss-fuzz; issues tracker) `[verify]`;
named here: libwebp CVE-2023-4863 (BLASTPASS; fixed libwebp 1.3.2) `[OBS]` public CVE, libpng
CVE-2018-13785, libtiff CVE-2016-5321-era files, libjpeg-turbo CVE-2020-35538-era files `[verify ids]`.
Mutation tools: radamsa (gitlab.com/akihe/radamsa) · zzuf (caca.zoy.org/wiki/zzuf) · AFL++
(github.com/AFLplusplus/AFLplusplus).

Local receipts used by this plan: `14.10-bid/console-watch.sh`, `ack-watchdog.sh`, `ds-watchdog.sh`,
`verdict-watch.sh`, `GO-LIVENESS.md`, `README-MISSION.md`, `operator-instructions-claude.md`,
`ps5-recon-20261014-170016/PS5-no-HDMI-interface-vectors-dossier.md` (§Q1a, §Q1e, §Q2a),
`device-audit-20261014.md`, `ps5-wake-README.md`, `luckma-hid_navigate.py`, `luckma-nav_sequence.py`,
`luckma-README.md`, `postjb-tools/write-chiaki-host.py`, `ps5-lan-research/ps5-webkit-remote-loader/current.txt`
(probe-pointer convention), `FINDINGS-SYNTHESIS-20261018.md`.

---

## Appendix A — mock session log (schema illustration only)

```json
{"t":"2026-10-20T15:30:00Z","ev":"NOTE","note":"session jpg-b01 start; drive D2; manifest sha256 ok; baseline smoke PASS"}
{"t":"2026-10-20T15:33:10Z","ev":"OPEN","fid":"f00_jpg_seed_vanilla","seq":1,"src":"macro:photo-open"}
{"t":"2026-10-20T15:33:24Z","ev":"CLOSE","fid":"f00_jpg_seed_vanilla","seq":1,"note":"OK rendered"}
{"t":"2026-10-20T15:39:02Z","ev":"OPEN","fid":"f07_jpg_cve_cve2018-13785","seq":8,"src":"macro:photo-open"}
{"t":"2026-10-20T15:39:05Z","ev":"ANOMALY","fid":"f07_jpg_cve_cve2018-13785","note":"chiaki frame frozen; ICMP+DDP still alive -> HANG class"}
```

## Appendix B — recon output matrix (filled during Phase R, not now)

| family | surface | accepted? | macro | notes |
|---|---|---|---|---|
| `[UNK]` | `[UNK]` | `[UNK]` | `[UNK]` | to be produced as `recon-map.md` |

*End of plan. Next executable steps: (1) user review of this document, (2) Phase P0 dry-runs,
(3) Phase R recon with the baseline drive.*
