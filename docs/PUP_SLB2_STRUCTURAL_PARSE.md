# PS5 PUP (SLB2/BLS container) — structural parse dossier — 2026-10-18

Scope: local-only, read-only structural parse of `PS5UPDATE.PUP`
(1,261,408,256 bytes, mtime 2026-10-15 02:47). No decryption, no key usage, no console/network
target touched, nothing uploaded. Segment payloads are encrypted; this parse covers the plaintext
container/header layers and documents the encrypted layers by construction (source-cited).

Tag key: **[OBS]** measured from the file's own bytes (receipts = offset + raw bytes).
**[INF]** inference drawn from measurements and/or cited sources. **[UNK]** unknown/undetermined —
no guessing.

Companion machine-readable file: `pup-slb2-entries-20261018.json` (same directory).

---

## 1. Artifact identity

- [OBS] Path `PS5UPDATE.PUP`; size = 1,261,408,256 bytes = `0x4B2F9000` (stat + hex conversion).
- [OBS] Hashes (each streamed once over the file, read-only; never fully loaded into memory):
  - md5 = `f7853a0fa97a9a7828ac548798012782`
  - sha1 = `6fec57462c48557210170227cbe7e2f1c3872bb4`
  - sha256 = `c17384946df6e5c85b2d72cbeee2057b165bf90279d9e2a86d527d0778cdaaf6`
- [OBS] First 4 bytes at 0x00: `53 4c 42 32` = ASCII "SLB2" (little-endian u32 `0x32424C53`).
- [OBS] On-disk filename is `PS5UPDATE.PUP`, but the only plaintext name string embedded in the file is
  `PS5UPDATE1.PUP` at 0x30 — they differ (see §4, §8).
- [OBS] Full-file magic scan (chunked, `grep -abo` + python 4 MiB chunk walk):
  exactly **2** `SLB2` matches (0x0, 0x58DD5EE), exactly **1** `54 14 F5 EE` (= `0xEEF51454` LE) match
  (0x400), 0 ELF magics, 1 `PS5UPDATE` string.
- [INF] This file is a retail PS5 system-update PUP. FW 14.10 identification: TitaniaPy's
  `RESEARCH_POST.md` lists a real FW 14.10 retail `PS5UPDATE.PUP` of **identical size (1,261,408,256 B)
  and identical BLS entry size (0x4B2F8A3D)**, plus "Version 3, 1 inner entry (`PS5UPDATE1.PUP`),
  offset 0x400" (deepkicks/TitaniaPy @ main). No plaintext firmware version string exists in the file
  (`version_name.xml` is inside the encrypted region), so this identification is [INF], not [OBS].

## 2. High-level layout map (measured)

| Range | Length | What | Tag |
|---|---|---|---|
| 0x00000–0x00004 | 4 | `SLB2` magic | [OBS] |
| 0x00004–0x00030 | 44 | BLS header fields (version=3, flags, file_count=1, block_count, 12×0x00) | [OBS] |
| 0x00030–0x00050 | 32 | entry[0].name = `"PS5UPDATE1.PUP"` + NUL padding | [OBS] |
| 0x00050–0x00200 | 432 | zeros (unused entry slots; capacity 10×48 B) | [OBS] |
| 0x00200–0x00220 | 32 | digest-like blob A (`4c294437…cd03`) — role [UNK] | [OBS]/[UNK] |
| 0x00220–0x003E0 | 448 | zeros | [OBS] |
| 0x003E0–0x00400 | 32 | digest-like blob B (`ab52ba9e…a7fe`) — role [UNK] | [OBS]/[UNK] |
| 0x00400–0x4B2F8E3D | 1,261,406,781 | entry[0] data = encrypted inner PUP (`54 14 F5 EE` = `0xEEF51454`) | [OBS] |
| 0x4B2F8E3D–0x4B2F9000 | 451 | zeros (tail) | [OBS] |

Arithmetic receipts ([OBS]): `0x400 + 0x4B2F8A3D = 0x4B2F8E3D`; `0x4B2F8E3D + 0x1C3 = 0x4B2F9000` (file size).
Last nonzero byte of the file: `0xB2` at 0x4B2F8E3C; everything 0x4B2F8E3D..EOF is 0x00 (verified byte-wise).

## 3. BLS/SLB2 container header (32 bytes at 0x00) — fully parsed, plaintext

Raw header receipt [OBS] (0x00–0x50):

```
00000000  53 4c 42 32 03 00 00 00 00 00 01 00 01 00 00 00  SLB2............
00000010  c8 97 25 00 00 00 00 00 00 00 00 00 00 00 00 00  ..%.............
00000020  02 00 00 00 3d 8a 2f 4b 00 00 00 00 00 00 00 00  ....=./K........
00000030  50 53 35 55 50 44 41 54 45 31 2e 50 55 50 00 00  PS5UPDATE1.PUP..
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

Field table (struct: `bls_header` — LightningMods/ps5-pup-decrypt `include/bls.h`,
size enforced by `_Static_assert(sizeof(bls_header)==32)` in `source/checkheaders.c`):

| Off | Size | Struct field | Raw bytes | Value | Tag/source |
|---|---|---|---|---|---|
| 0x00 | 4 | magic | `53 4c 42 32` | "SLB2" (`0x32424C53` LE) | [OBS]; magic value checked in `source/decrypt.c`; psdevwiki: "Always 53 4C 42 32" |
| 0x04 | 4 | version | `03 00 00 00` | 3 | [OBS]; matches TitaniaPy "Both: Version 3" |
| 0x08 | 4 | flags | `00 00 01 00` | `0x00010000` | [OBS]; bit meaning [UNK] (only "flags" in source) |
| 0x0C | 4 | file_count | `01 00 00 00` | 1 | [OBS]; `decrypt.c` accepts 1..10; TitaniaPy: "1 inner entry" |
| 0x10 | 4 | block_count | `c8 97 25 00` | `0x002597C8` = 2,463,688 | [OBS]; ×512 = 1,261,408,256 = exact file size → self-consistency PASS |
| 0x14 | 12 | unknown | 12×`00` | 0 | [OBS]; meaning [UNK] |
| 0x20 | 48 | entry_list[0] | see §4 | — | [OBS] |

- [INF] psdevwiki says "0x30 File table". The measured entry table actually starts at 0x20
  (`entry_list` right after the 32-byte header); the wiki's 0x30 corresponds to the **name field of
  entry[0]** (entry+0x10), which is what appears at 0x30. Source of truth for the table offset is
  `bls.h`/`decrypt.c`, which parse `header->entry_list[i]` from a 32-byte header.
- [INF] Max 10 entries ⇒ table area = 0x20 + 10×48 = exactly 0x200, which is why blob A (§5) begins at 0x200.

## 4. Entry table (plaintext, fully parsed)

Record struct: `bls_entry`, 48 bytes (`include/bls.h`; `_Static_assert` size 48 in `checkheaders.c`):
`{ u32 block_offset; u32 size; u8 reserved[8]; char name[32]; }`.
There is **no id field and no flags field** in `bls_entry` (source-cited) — the entry is identified by name.

entry_count = 1 [OBS] (0x0C = `01 00 00 00`; matches TitaniaPy "1 inner entry"; `decrypt.c` constraint 1..10 PASS).

Entry 0 receipt [OBS] (0x20–0x50): `02 00 00 00 | 3d 8a 2f 4b | 00×8 | 50 53 35 55 50 44 41 54 45 31 2e 50 55 50 00…`

| Field | Raw bytes @ off | Value | Notes |
|---|---|---|---|
| block_offset | `02 00 00 00` @0x20 | 2 | [OBS]; absolute offset = 2×512 = 0x400 — `decrypt.c`: `input_base_offset = block_offset * 512` |
| size | `3d 8a 2f 4b` @0x24 | 0x4B2F8A3D = 1,261,406,781 | [OBS]; equals TitaniaPy's reported "BLS entry size" for FW 14.10 |
| reserved | 8×`00` @0x28 | 0 | [OBS] |
| name | `PS5UPDATE1.PUP\0…` @0x30 | ASCII | [OBS]; 14 chars + 18 NUL bytes of the 32-byte field; selects key type 1 (system update) on console per `decrypt.c` |
| id | — | [UNK]/absent | bls_entry has no id field (source: bls.h) |
| flags | — | [UNK]/absent | bls_entry has no flags field (source: bls.h) |
| digest fields | — | none in bls_entry | the 2×32-byte blobs live outside the struct (§5) |

Validation (§9): offset+size = 0x400+0x4B2F8A3D = 0x4B2F8E3D ≤ file size 0x4B2F9000 **[PASS]**;
single entry ⇒ no overlaps; gaps reported in §9.

## 5. Two 32-byte digest-like fields (outside the structs) — role [UNK]

`decrypt.c` reads exactly the first **0x400** bytes as the BLS header and submits that whole region to
the console ioctl `0xC0104401` ("VerifyBlsHeader"), so both blobs fall inside the console-verified
region [INF from source]. Positions measured [OBS]:

- Blob A @0x200 (32 B): `4c294437efcfa2b71856efd6a34f3f016929665d661fc34892c13d297f21cd03`
- blobs are separated by 0x1C0 (448) zero bytes; Blob B @0x3E0 (32 B): `ab52ba9e73e15573ca14ac47c312ae25e27f11472abd1959d4c4bda8a739a7fe`
- Blob B ends at exactly 0x400, i.e., flush against entry data start.
- [UNK] purpose. Negative results: neither blob equals sha256 of any tested region — entry data
  [0x400,0x4B2F8E3D), entry head-64, [0x0,0x50), [0x0,0x200), [0x0,0x3E0), [0x0,0x400),
  [0x20,0x50), [0x200,0x400), PUP header blob [0x400,0x1790), PUP blob minus the 16 plaintext bytes,
  data after the header blob, or the whole file; md5/sha1 spot checks also negative. They are
  plausibly console-verified hashes/signature material (32 bytes resembles SHA-256), but this is not
  proven → [UNK].

Context receipt [OBS] (0x1f0–0x240 and 0x3d0–0x440):

```
000001f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000200  4c 29 44 37 ef cf a2 b7 18 56 ef d6 a3 4f 3f 01  L)D7.....V...O?.
00000210  69 29 66 5d 66 1f c3 48 92 c1 3d 29 7f 21 cd 03  i)f]f..H..=).!..
00000220  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...
000003d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003e0  ab 52 ba 9e 73 e1 55 73 ca 14 ac 47 c3 12 ae 25  .R..s.Us...G...%
000003f0  e2 7f 11 47 2a bd 19 59 d4 c4 bd a8 a7 39 a7 fe  ...G*..Y.....9..
00000400  54 14 f5 ee 10 01 01 32 04 00 00 00 b0 05 e0 0d  T......2........
00000410  15 8b b5 6a 2a 44 5d f2 87 ca 84 a5 bf 96 d4 a3  ...j*D].........
00000420  60 aa 28 67 61 19 e4 05 98 2f f3 26 a2 91 5f 28  `.(ga..../.&.._(
00000430  a8 30 22 da 28 cd 72 40 2f b4 be 29 d5 5c f1 c9  .0".(.r@/..).\.(
```

## 6. Payload: inner PUP (`0xEEF51454`) at 0x400

Plaintext portion — first 16 bytes only [OBS]: `54 14 f5 ee 10 01 01 32 04 00 00 00 b0 05 e0 0d`
(parsed per `pup_file_header`, 16 B, `checkheaders.c` static assert; same layout in TitaniaPy `pup.py`):

| Off (abs) | Raw bytes | Field | Value | Tag/source |
|---|---|---|---|---|
| 0x400 | `54 14 f5 ee` | magic | `0xEEF51454` | [OBS]; `decrypt.c` + TitaniaPy `PUP_MAGIC` |
| 0x404 | `10 01 01 32` | unknown_04 | `0x32010110` | [OBS]; TitaniaPy: "likely format version, not firmware version"; identical on FW 14.00 & 14.10 → [INF] constant; exact meaning [UNK] |
| 0x408 | `04 00` | unknown_08 | 4 | [OBS]; meaning [UNK] |
| 0x40A | `00` | flags | 0 | [OBS]; `decrypt.c`: bit0 set = "network pup", rejected — here 0 (ok) |
| 0x40B | `00` | unknown_0B | 0 | [OBS]; meaning [UNK] |
| 0x40C | `b0 05` | header_size | 0x05B0 = 1456 | [OBS]; same value on FW 14.00/14.10 per TitaniaPy |
| 0x40E | `e0 0d` | hash_size | 0x0DE0 = 3552 | [OBS]; same note |

- [INF] Encrypted header blob size = header_size + hash_size = 0x1390 = 5008 bytes:
  `decrypt.c` computes `header_size = unknown_0C + unknown_0E` and sends 16 plaintext bytes +
  0x1390 ciphertext bytes to the console ioctl `0xC0184402` (`encsrv_decrypt_header`). So ciphertext
  region = **[0x410, 0x1790)**, sha256 `a4ad30374f6525e7defc6661d89c53635f755e53a04f55778612add740535708` [OBS].
- [INF] Extended header is encrypted, not merely compressed: TitaniaPy reports 256/256 bytes differ
  between FW 14.00 and 14.10 there and 7.15–7.29 bits/byte; independently measured here [OBS]:
  byte-entropy of [0x410,0x1410) = 7.9538 bits/byte, and 8.0000 bits/byte over the entire
  0x4B2F8A3D-byte inner image — consistent with ciphertext.
- [INF] Segment table location (from `decrypt.c`): after console-side header decryption, the parser
  casts `header_data` to `pup_header` and reads segments at `header_data[0x20]`; each `pup_segment`
  is 32 B (`{ u32 flags; u32 flags2; s64 offset; u64 compressed_size; u64 uncompressed_size; }`).
  In this file that table would sit at absolute 0x420 — **inside the encrypted blob** ⇒ all values
  [UNK] here. Only a size estimate is possible from the plaintext fields ([INF], TitaniaPy: "~44
  segments at 32 bytes each" from header_size 0x5B0).
- [INF] Segment flag semantics (source-cited, applies only post-decryption): id = `(flags>>20)&0xFFF`;
  type = `(flags>>28)&0xF` with 0xE = additional signature (verified with "additional"=1) and
  F = watermark (additional=0); bit 0x8 = compressed; bit 0x800 = blocked (block table segment has
  bit 0x1 and matching id); block_size = `1 << (((flags & 0xF000) >> 12) + 12)`; block pointer mask
  = `(flags2 & 1) ? 0x1ff : 0xf` (LightningMods `decrypt.c`; deepkicks `pup.py`).
- Reference-only name mapping for decrypted segment ids (source: deepkicks/TitaniaPy `keys.py`,
  attributed there to psdevwiki; included in the JSON under `inner_pup.segment_names_reference`).
  Examples: 0x04 mbr.bin, 0x05 kernel.bin, 0x0B titania.bls, 0x0E eap_kbl.bin, 0x10 emc_salina_c.bls,
  0x12 usb_pdc_salina_c.bls, 0x103 oberon_sec_ldr_c.bin, 0x201 wlanbt.bin, 0x203 ssd0.system_b,
  0x207 ssd0.preinst. **No segment was decrypted or identified from this file's bytes.**

## 7. Version strings / metadata found in plaintext

- [OBS] `PS5UPDATE1.PUP` @0x30 (raw: `50 53 35 55 50 44 41 54 45 31 2e 50 55 50`), NUL-padded to 32 B.
- [OBS] Version numbers in headers: BLS version = 3; inner PUP magic `0xEEF51454`; unknown_04 `0x32010110`.
- [OBS] No firmware version string in plaintext anywhere (`version_name.xml`, per segment names, is
  inside the encrypted region).
- [INF] FW identity 14.10 via source match (see §1); [UNK] exact build string.

## 8. Negative results / coincidences (scan receipts)

- [OBS]+[INF] Second `SLB2` at 0x58DD5EE (`53 4c 42 32 43 dc f4 28 …`) is inside the encrypted image;
  its "version" bytes are `43 dc f4 28` ≠ 3, and it is unaligned — coincidence in ciphertext.
  Expected hits of a fixed 4-byte pattern in ~1.26 GB of random data ≈ 0.3; observed 1 → consistent.
- [OBS] `0xEEF51454`-big-endian byte pattern `ee f5 14 54` occurs once at 0x1D61756D, inside encrypted
  data → coincidence.
- [OBS] ASCII `PUP` occurs 76×, `posbp=` once at 0x4B2F8E10 — all inside the encrypted image;
  consistent with random data (not evidence of plaintext structure).
- [OBS] No ELF (0x7f454c46) anywhere.
- [OBS] Digest-candidate recomputation for blobs A/B: all negative (list in JSON §negative_results…).

## 9. Validation summary

- [OBS] entry_count = 1 = header file_count (0x0C) **[PASS]**; within `decrypt.c` constraint 1..10 **[PASS]**.
- [OBS] Entry bounds: [0x400, 0x4B2F8E3D) ⊆ [0, 0x4B2F9000) **[PASS]**.
- [OBS] Overlaps: none (single entry).
- [OBS] Gaps (all-ZERO verified byte-wise):
  - [0x050, 0x200) = 432 B — unused entry slots (capacity 10×48 B, one used).
  - [0x220, 0x3E0) = 448 B — between the two digest-like blobs.
  - [0x4B2F8E3D, 0x4B2F9000) = 451 B — tail after entry data.
- [OBS] Arithmetic self-checks: block_count×512 = file size; entry end + tail = file size (§2).
- [OBS] The console verifies the first 0x400 bytes (VerifyBlsHeader, per `decrypt.c`) — all parsed
  fields except the entry payload fall inside that verified region.

## 10. Sources cited (exact)

1. psdevwiki, PS5 "PUP" page — live URL `https://www.psdevwiki.com/ps5/PUP` returned HTTP 403
   (Cloudflare) from this host; used archived snapshot
   `https://web.archive.org/web/20250110104341id_/https://www.psdevwiki.com/ps5/PUP`
   (page last edited 2023-06-10, oldid=1901). Taken: magic bytes `53 4C 42 32`; "0x30 File table";
   update index order list (segment ids for usb_pdc_salina_c0.bls=18, emc_salina_c0.bls=16,
   titania.bls=11, eap_kbl.bin=14, mbr.bin=4, oberon_sec_ldr_c0.bin=259, kernel.bin=5,
   wlanbt.bin=513, ssd0.system_b=515, ssd0.system_ex_b=516, ssd0.preinst=519, bluray.bin=2000).
2. LightningMods/ps5-pup-decrypt (branch `master`; on-console decrypt tool) —
   `https://github.com/LightningMods/ps5-pup-decrypt`. Taken: `include/bls.h` (bls_header/bls_entry
   layouts), `source/checkheaders.c` (struct sizes 32/48/16/32/32/8), `source/decrypt.c` (magic
   `0x32424C53`/`0xEEF51454`, file_count 1..10, first-0x400 read + VerifyBlsHeader, `block_offset
   ×512`, PUP header-blob size = unknown_0C+unknown_0E, segments at header+0x20, segment flag
   semantics, type 1 = PS5UPDATE1.PUP / type 0 = PS5UPDATE2.PUP), `include/pup.h`.
   (Note: `theflow0/ps5-pup-decrypt` returned HTTP 404 on raw.githubusercontent.com for both `main`
   and `master` — no such public repo found; the `theflow0` GitHub account exists but exposes no
   public repos via the API. Mirrors `zecoxao/ps5-pup-decrypt` and `aydencharles/ps5-pup-decrypt`
   were cross-checked and carry the same on-console tool (same core sources `checkheaders.c`,
   `decrypt.c`, `decryptio.c`, `encryptsrv.c`, `main.c` and headers `bls.h`, `pup.h`,
   `encryptsrv_args.h`); the LightningMods copy was the one read and cited.)
3. deepkicks/TitaniaPy (branch `main`; PC-side parser/research) —
   `https://github.com/deepkicks/TitaniaPy`. Taken: `pup.py` (PUP_MAGIC 0xEEF51454, header/segment
   parser, flag bitfields), `keys.py` (SEGMENT_NAMES id→filename), `RESEARCH_POST.md` (FW 14.10:
   1,261,408,256 B / entry 0x4B2F8A3D; FW 14.00: 1,260,600,832 B / 0x4B2339D5; identical plaintext
   headers 0x32010110/0x5B0/0xDE0; encrypted extended header; entropy 7.15–7.29; ioctl table
   `0xC0104401` VerifyBlsHeader, `0xC0184402` DecryptHeader(type), `0xC0184403`/`0xC0184404`
   additional-sign/watermark, `0xC0184405` DecryptSegment, `0xC0284406` DecryptSegmentBlock).

Other files consulted from those repos (checkheaders/pup.h/encryptsrv_args for structure sizes and
ioctl argument shapes) are part of the same repos. No key material was used in this analysis and none
is reproduced in this dossier.

## 11. Uncertainty ledger

1. [UNK] Roles of the two 32-byte fields at 0x200 / 0x3E0 (tested hash candidates all negative;
   plausibly signature/digest material — unproven).
2. [UNK] Meaning of BLS `flags` = 0x00010000 and inner PUP `unknown_04` = 0x32010110, `unknown_08` = 4.
3. [UNK] Inner PUP segment table contents (count, ids, offsets, sizes): entirely inside the encrypted
   header blob [0x410, 0x1790); recoverable only with console-side decryption (out of scope).
4. [UNK] Tail-zero purpose (451 B at end of file).
5. [UNK] Exact firmware build string (encrypted); FW 14.10 is [INF] via size/entry-size source match.
6. [INF] Second `SLB2` at 0x58DD5EE and other ASCII hits inside ciphertext are coincidences.

## 12. Method (reproducible, read-only)

- Header/metadata reads: python3 `seek`+`read` ≤ 0x10000 bytes; hexdumps of key regions.
- Magic scans: `LC_ALL=C grep -abo` + python 4 MiB chunked `bytes.find` over the whole file.
- Hashes: single streamed pass for md5/sha1/sha256; region hashes streamed in 8–16 MiB chunks.
- Zero-region checks and bounds checks enumerated in §9; entropy via byte-histogram over regions.
- The 1.26 GB file was never loaded into memory as a whole.
- Scratch used: `/tmp/opencode/pup-parse/`. No files outside the two deliverables were created or
  modified in `~/Work`.

## Appendix A — entry[0] head-64 (input for `sha256_head64`)

Raw 64 bytes @0x400 [OBS]:
`54 14 f5 ee 10 01 01 32 04 00 00 00 b0 05 e0 0d 15 8b b5 6a 2a 44 5d f2 87 ca 84 a5 bf 96 d4 a3
60 aa 28 67 61 19 e4 05 98 2f f3 26 a2 91 5f 28 a8 30 22 da 28 cd 72 40 2f b4 be 29 d5 5c f1 c9`
sha256 = `f1bf51b3cb3538996d83b896b3d41bac8d52cb875fbb2eb3e1c794849dfb12c5`

## Appendix B — file tail receipt

```
4b2f8df0  b8 08 0f 67 d9 a5 f6 3a 6a e8 21 f6 e5 ea 9c 37  ...g...:j.!....7
4b2f8e00  36 17 9a 33 69 0e 13 74 2d c5 bb ce 86 a6 9f ea  6..3i..t-.......
4b2f8e10  70 6f 73 62 70 3d b0 30 a7 02 16 42 6a 29 dc 9d  posbp=.0...Bj)..
4b2f8e20  a2 99 26 df a1 d4 57 da db a4 4d c3 49 c6 2f 2e  ..&...W...M.I./.
4b2f8e30  35 15 a5 88 b4 e2 15 95 47 b6 bc 80 b2 00 00 00  5.......G.......
4b2f8e40  00 00 00 00 … (all 0x00 to EOF at 0x4B2F9000)
```
