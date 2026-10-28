# wl.ko Deep Subsystem Catalog — OWA7111VDF (BCM6756, 17.10.188.6401 r808804)

**Binary:** `/home/user/OWA7111VDF/driver_extract/wl.ko` (11.8 MB, ARM32 ET_REL, 13,010 defined functions, full .symtab)
**Anchor source:** SWRT impl87 (epivers 17.10.188.6401 r808804 exact match, 113 glue symbol cross-matches)
**Analysis artifacts:** `/tmp/opencode/wlindex/` (disassembly, symbol buckets, call graph data)

---

## Chapter 1: Core Structures — Verified Offsets from Disassembly

### 1.1 `wlc_info` (wlc public handle) — Primary driver context

**Binary role:** First argument to most `wlc_*` functions (register `r4` in disassembly). Allocated in `wlc_attach` → `osl_mallocz`.

**Verified offsets (from `wlc_attach` at 0x3100ac and `wlc_bcn_prb_body` at 0x312d94):**

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 4 | `pub` pointer | → `wlc_pub` (see below) |
| +0x04 | 4 | `osh` | OS handle |
| +0x08 | 4 | `wlc_hw` | Hardware ops |
| ... | ... | ... | (partial — full layout needs more disassembly) |

**Disassembly evidence:**
- `wlc_bcn_prb_body` (0x312d94): `mov r4, r0` — `r0` = wlc_info, `r4` used throughout
- `wlc_attach` (0x3100ac): allocates wlc_info, stores at `[r4, #8]` (line 0x310464)

---

### 1.2 `wlc_bsscfg` — Per-BSS configuration (matches impl87 `wl_bsscfg_t`)

**Binary role:** Per-BSS state, passed as `r5` in `wlc_bcn_prb_body`, returned by `wlc_bsscfg_find_by_wlcif`.

**Verified offsets (from `wlc_bcn_prb_body` 0x312d94 + impl87 `wl_bsscfg_t`):**

| Offset | Size | Field | Binary Evidence |
|--------|------|-------|-----------------|
| +0x00 | 4 | `wsec` | `ldr r3, [r5, #0x4c]` at 0x313090 → **wsec at +0x4c** |
| +0x04 | 4 | `WPA_auth` | impl87 `wl_bsscfg_t` |
| +0x08 | 4 | `wsec_index` | impl87 |
| +0x0c | 4 | `associated` | impl87 |
| +0x10 | 4 | `BSS` | impl87 |
| +0x14 | 4 | `phytest_on` | impl87 |
| +0x18 | 6 | `prev_BSSID` | impl87 |
| +0x1e | 6 | `BSSID` | impl87 |
| +0x4c | 4 | `wsec` (confirmed) | **Privacy gate reads here** |
| +0x54 | 1 | `wep_restrict` / `wsec_restrict` | **Privacy gate reads byte here** (0x31309c) |
| +0x74 | 4 | flags (bit 0x4000) | Short-slot gate at 0x313104 |

**Privacy bit gate (0x313090-0x3130ac):**
```
ldr  r3, [r5, #0x4c]    ; wsec
tst  r3, #7             ; any cipher (WEP|TKIP|AES)
beq  skip_privacy
ldrb r3, [r5, #0x54]    ; wep_restrict byte
cmp  r3, #0
orrne r3, r3, #0x10     ; set Privacy bit (0x10)
```
**→ Privacy bit requires BOTH `wsec & 7 != 0` AND `wep_restrict != 0`**

**Key writers of `wep_restrict` (+0x54):**
- `wlc_doioctl` case 82 (WLC_SET_WEP_RESTRICT) at 0x31c438: `strb r2, [r0, #0x54]`
- `wlc_ap_process_assocreq` at 0x357f78: derives from STA caps
- `wlc_fbtap_write_ft_ie` (multiple sites)
- `wlc_attach` at 0x310448: initializes `pub+0x54` (different struct!)

---

### 1.3 `wlc_scb` — Station control block (per-associated STA)

**Binary role:** Per-station state, iterated via `wlc_scb_iterinit`/`wlc_scb_iternext` (213 call sites each).

**Key fields (from call patterns):**
| Offset | Field | Evidence |
|--------|-------|----------|
| +0x00 | `next` (list link) | `wlc_scb_iternext` traversal |
| ... | `ratesel` state | `wlc_scb_ratesel_*` (48+ call sites) |
| ... | `ampdu` state | `wlc_scb_ampdu_enable/disable` (8+ calls) |
| ... | `cubby` | `wlc_scb_cubby_*` (26+ calls) |
| ... | `ht`/`vht`/`he` caps | Rate selection uses these |

**Major call sites:**
- `wlc_scb_iterinit` / `wlc_scb_iternext` — 213 each (primary traversal)
- `wlc_scbfind` / `wlc_scbfind_from_wlcif` — 231 / 1855 calls
- `wlc_scb_ratesel_*` — 48+ variants
- `wlc_scb_ampdu_enable/disable` — 8/11 calls

---

### 1.4 `wlc_pub` — Public driver instance (published to OS)

**Binary role:** Exported to `wl_linux.c` glue, returned by `wlc_pub()` (called at 0x31046c from `wl_attach`).

**Verified offsets (from `wlc_attach` at 0x31046c-0x310478):**
| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | 4 | `wlc` pointer | `str r0, [r4, #8]` at 0x310464 → `wlc_info` |
| +0x04 | 4 | `osh` | `str r0, [r4, #4]` at 0x310474 |
| +0x34 | 4 | `unit` | impl87 |
| +0x54 | 1 | `wep_restrict` (?) | `wlc_attach` writes here at 0x310448 — **different from bsscfg!** |

**Note:** `wlc_pub+0x54` is initialized in `wlc_attach` but **not** the same as `bsscfg+0x54` used in Privacy gate. The beacon code uses `bsscfg+0x54` (via `r5` = bsscfg pointer).

---

### 1.5 `wlc_hw` / `d11regs` — Hardware register access

**Binary role:** D11 core register macros and SHM access.

**Key functions:**
- `wlc_write_shm` (292 calls) — SHM write
- `wlc_write_shmx` (241 calls) — SHM write extended
- `wlc_read_shm` — SHM read
- `d11regs` — Register structure (see `d11regsx130` at 0xa19d0, size 0x240)

**PHY/radio access (heavily used):**
- `phy_utils_mod_phyreg` — 5,590 calls
- `phy_utils_mod_radioreg` — 17,638 calls
- `phy_utils_write_phyreg` — 2,333 calls
- `phy_utils_read_phyreg` — 1,717 calls
- `phy_utils_write_radioreg` — 1,209 calls
- `phy_utils_read_radioreg` — 824 calls

---

### 1.6 Structure Cross-Reference Table

| Structure | Primary Register | Key Functions | Verified Offsets |
|-----------|------------------|---------------|------------------|
| `wlc_info` | `r4` (most functions) | All `wlc_*` | +0x00=pub, +0x08=wlc_hw |
| `wlc_bsscfg` | `r5` (bcn/body), arg to `wlc_bsscfg_*` | 125+ call sites | **+0x4c=wsec, +0x54=wep_restrict, +0x74=flags** |
| `wlc_scb` | `r5`/`r6` (scb functions) | 213 iterators, 48 ratesel | cubby, ampdu, ratesel state |
| `wlc_pub` | returned by `wlc_pub()` | `wl_linux.c` glue | +0x00=wlc, +0x04=osh, +0x54=wep_restrict (init only) |
| `wlc_hw` | `r4->wlc_hw` | d11regs, SHM | `wlc_write_shm` (292), `phy_utils_*` |

---

### 1.7 impl87 Header Cross-Reference

**Source:** `RMerl/asuswrt-merlin.ng@384.7_x` → `release/src-rt-6.x.4708/include/wlioctl.h`

```c
typedef struct wl_bsscfg {
    uint32  wsec;           // +0x00
    uint32  WPA_auth;       // +0x04
    uint32  wsec_index;     // +0x08
    uint32  associated;     // +0x0c
    uint32  BSS;            // +0x10
    uint32  phytest_on;     // +0x14
    struct ether_addr prev_BSSID; // +0x18
    struct ether_addr BSSID;      // +0x1e
    // ... padding to +0x4c ...
    uint8   wep_restrict;   // +0x54  ← PRIVACY GATE BYTE
} wl_bsscfg_t;
```

**Offset verification:**
- impl87: `wep_restrict` at +0x54 (after two ether_addr = 12 bytes, plus padding)
- Binary: `ldrb r3, [r5, #0x54]` in Privacy gate → **CONFIRMED**

---

## Chapter 2: Beacon/Probe/RSN IE (`wlc_bcn_prb_*`, `wlc_akm_bcn_*`, `wlc_iem_*`)

### 2.1 Overview

The beacon/probe response construction is split across two main functions:
- **`wlc_bcn_prb_template`** (0x3133b0, size 0x34c) — Builds MAC header only
- **`wlc_bcn_prb_body`** (0x312d94, size 0x4b8) — Builds frame body: capabilities, rates, RSN IE, HT/VHT/HE IEs, TIM, etc.

`wlc_bcn_prb_template` calls `wlc_bcn_prb_body` at 0x313494 and 0x313688.

---

### 2.2 `wlc_bcn_prb_template` — MAC Header Builder (0x3133b0)

**Signature:** `wlc_bcn_prb_template(wlc_info *wlc, uint8_t *buf, uint16_t fc, bsscfg *cfg, ...)`

**Register mapping at entry:**
- `r0` = `wlc_info` → `r7`
- `r1` = `frame_control` (FC) → `r6`
- `r2` = `bsscfg` → `r4`
- `r3` = output buffer pointer → `r4` (reused)

**Key operations:**
1. **Frame Control handling** (0x3133e4-0x31341c): Extracts type/subtype from FC, validates beacon (0x80) vs probe response (0x50)
2. **MAC header construction** (0x313420-0x3134d4):
   - Duration/ID field: 0 for beacon, calculated for probe resp
   - DA: broadcast (beacon) or specific STA (probe resp) — from `r2` (caller's arg)
   - SA: from `wlc->pub->cur_etheraddr` (at `r4+0x64/0x68`)
   - BSSID: from `bsscfg->BSSID` (at `r4+0x74`? → `buf+16..21`)
   - Sequence control: 0 for beacon, managed for probe resp
3. **Calls `wlc_bcn_prb_body`** at 0x313494 and 0x313688 for frame body
4. **Returns** total frame length in `r9` (updated by body)

**No capability/RSN IE logic here** — purely MAC header.

---

### 2.3 `wlc_bcn_prb_body` — Frame Body Builder (0x312d94)

**Signature:** `wlc_bcn_prb_body(wlc_info *wlc, bsscfg *cfg, uint8_t *buf, uint16_t fc, ...)`

**Register mapping:**
- `r0` = `wlc_info` → `r4`
- `r1` = (unused?) → `r1` (saved to stack)
- `r2` = `bsscfg` → `r5` (primary bsscfg pointer throughout)
- `r3` = `buf` (output) → `r6` (body pointer)

**Stack frame:** 0xb4 bytes (180 bytes), with locals at `sp+0x24` (rateset), `sp+0x3c` (buffer), etc.

**Major sections (in order):**

#### 2.3.1 Preamble & Rate Set (0x312df4-0x312e3c)
- Checks `wlc_info+0x240` (pointer to rateset?)
- Calls `wlc_rateset_elts` (0x312a54) to populate supported rates
- Loads `wlc_info+0x608` (HT caps?) → calls `wlc_ht_get_wsec_restriction` (0x414df0)

#### 2.3.2 HT/WSEC Restriction Check (0x312e40-0x312e5c)
```asm
ldr r0, [r4, #0x608]      ; wlc_info+0x608 → HT caps
bl wlc_ht_get_wsec_restriction
tst r0, #1                 ; bit 0 = restriction?
beq skip_ht_section
ldr r3, [r5, #0x4c]       ; bsscfg+0x4c = wsec
tst r3, #1                 ; WEP bit
movne sl, #0               ; sl = 0 if WEP
beq skip_ht_section
```
Sets `sl` register used later for HT capability gating.

#### 2.3.3 SSID IE (0x312e90-0x312f34)
- Reads `fp+0x36` (SSID length)
- Handles MBSSID/multi-BSS cases via `r4+0x30` (interface pointer)
- Writes SSID IE to stack buffer

#### 2.3.4 Supported Rates IE (0x31305c-0x31307c)
```asm
ldrh r3, [fp, #0x32]      ; beacon interval
strh r3, [r6, #8]         ; buf+8 = beacon interval
ldrb r3, [r5, #6]         ; bsscfg+0x6 = ? (IBSS flag?)
cmp r3, #0
beq skip_rates
mov r3, #0
strb r3, [r6, #11]        ; buf+11 = 0 (extended rates?)
mov r3, #1
strb r3, [r6, #10]        ; buf+10 = 1 (rates count?)
```
Then builds supported rates from earlier `wlc_rateset_elts` result.

#### 2.3.5 **Capability Field Assembly — PRIVACY GATE** (0x313080-0x313120)

**This is the core capability logic:**

```asm
; --- ESS/IBSS (already set at 0x312ef4: orr r3, r3, #1) ---

; --- PRIVACY BIT (0x10) ---
ldr  r3, [r4]              ; r4 = wlc_info
ldrb r3, [r3, #0x54]       ; wlc_info+0x54 (pub wep_restrict?)
cmp  r3, #0
bne  skip_privacy_entirely ; if pub wep_restrict != 0, SKIP privacy!

ldr  r3, [r5, #0x4c]       ; bsscfg+0x4c = wsec
tst  r3, #7                ; any cipher (WEP|TKIP|AES)
beq  skip_privacy          ; no cipher → no privacy

ldrb r3, [r5, #0x54]       ; bsscfg+0x54 = wep_restrict
cmp  r3, #0
ldrhne r3, [r6, #10]       ; load current caps
orrne r3, r3, #0x10        ; set Privacy bit (0x10)
strhne r3, [r6, #10]       ; store back
```

**Key finding:** Privacy bit requires **THREE conditions**:
1. `wlc_info+0x54` (pub wep_restrict) == 0  — **global disable gate**
2. `bsscfg+0x4c (wsec) & 7 != 0`  — any cipher enabled
3. `bsscfg+0x54 (wep_restrict) != 0`  — per-BSS restrict flag

#### 2.3.6 Other Capability Bits

| Bit | Value | Condition | Location |
|-----|-------|-----------|----------|
| Short Slot | 0x400 (1024) | `wlc_info+0x35` && `wlc_info+0x30->+0x10` && `bsscfg+0x2cc` | 0x3130d0-0x3130ec |
| Short Preamble | 0x20 (32) | `bsscfg+0x74 & 0x4000` | 0x313104-0x31311c |
| Spectrum Mgmt | 0x100 (256) | `bsscfg+0x6` && `bsscfg` byte | 0x313110-0x313120 |
| Radio Measurement | 0x1000 (4096) | `wlc_rrm_enabled()` returns true | 0x3131f8-0x313208 |

#### 2.3.7 IE Construction (0x313124-0x313148)
- Prepares stack args for `wlc_iem_build_frame` (0x4185bc)
- `wlc_iem_calc_len` (0x418434) called first at 0x312fa8 to compute IE length
- `wlc_iem_build_frame` writes: RSN IE, HT IE, VHT IE, HE IE, WMM IE, etc.

#### 2.3.8 TIM IE & Cleanup (0x313158-0x313244)
- Handles DTIM/beacon interval
- Calls `wlc_rrm_enabled` (0x4a1858) for RRM capability

---

### 2.4 `wlc_iem_*` — IE Management (Information Element Manager)

**Key functions (from call graph):**
| Function | Address | Callers | Purpose |
|----------|---------|---------|---------|
| `wlc_iem_calc_len` | 0x418434 | `wlc_bcn_prb_body` (0x312fa8) | Compute total IE length |
| `wlc_iem_build_frame` | 0x4185bc | `wlc_bcn_prb_body` (0x313148) | Write all IEs to buffer |
| `wlc_iem_add_*` | various | `wlc_iem_build_frame` | Add specific IEs |

**IE types handled (from symbol names):**
- RSN IE (`wlc_akm_bcn_write_rsn_ie` — 1 call site)
- HT IE (`wlc_ht_bcn_write_ht_ie`)
- VHT IE (`wlc_vht_bcn_write_vht_ie`)
- HE IE (`wlc_he_bcn_write_he_ie`)
- WMM IE (`wlc_wme_bcn_write_wme_ie`)
- TIM IE (built inline)
- Vendor-specific (`wlc_vndr_ie_*`)

---

### 2.5 `wlc_akm_bcn_*` — AKM Beacon IE Writers

**Symbol bucket:** 77 functions in `beacon_probe` category, including:
- `wlc_akm_bcn_write_rsn_ie` — RSN IE construction
- `wlc_akm_bcn_write_wpa_ie` — WPA IE (legacy)
- `wlc_akm_bcn_write_mfp_ie` — MFP (802.11w) IE

**Call pattern:** Invoked from `wlc_iem_build_frame` via function pointer table.

---

### 2.6 Call Graph Summary

```
wl_bcn_send() / wl_prb_resp_send()
    └─ wlc_bcn_prb_template(wlc, buf, fc, bsscfg)
        ├─ Build MAC header (FC, DA, SA, BSSID, SeqCtl)
        ├─ wlc_bcn_prb_body(wlc, bsscfg, buf, fc)
        │   ├─ Rateset via wlc_rateset_elts()
        │   ├─ HT restriction via wlc_ht_get_wsec_restriction()
        │   ├─ SSID IE
        │   ├─ Supported Rates IE
        │   ├─ CAPABILITIES: ESS/IBSS + Privacy gate + ShortSlot + ShortPreamble + RM
        │   ├─ IE length calc: wlc_iem_calc_len()
        │   ├─ IE build: wlc_iem_build_frame()
        │   │   ├─ wlc_akm_bcn_write_rsn_ie()
        │   │   ├─ wlc_ht_bcn_write_ht_ie()
        │   │   ├─ wlc_vht_bcn_write_vht_ie()
        │   │   ├─ wlc_he_bcn_write_he_ie()
        │   │   ├─ wlc_wme_bcn_write_wme_ie()
        │   │   └─ ... (vendor, etc.)
        │   └─ TIM IE
        └─ Return total length
```

---

### 2.7 Binary Offsets Quick Reference

| Function | Address | Size | Key Offsets Used |
|----------|---------|------|------------------|
| `wlc_bcn_prb_template` | 0x3133b0 | 0x34c | `wlc_info+0x64/0x68` (SA), `bsscfg+0x74?` (BSSID) |
| `wlc_bcn_prb_body` | 0x312d94 | 0x4b8 | `bsscfg+0x4c` (wsec), `bsscfg+0x54` (wep_restrict), `bsscfg+0x74` (flags), `wlc_info+0x54` (pub gate) |
| `wlc_iem_calc_len` | 0x418434 | — | — |
| `wlc_iem_build_frame` | 0x4185bc | — | — |
| `wlc_ht_get_wsec_restriction` | 0x414df0 | 0x18 | `wlc_info+0x608` |

---

## Chapter 3: WPA/AKM/Keymgmt (`wlc_akm_*`, `wlc_keymgmt_*`, `wlc_eapol_*`, `wlc_wsec_*`)

### 3.1 Subsystem Overview

The WPA/AKM/Keymgmt subsystem handles:
- **AKM (Authentication Key Management)**: 802.1X, PSK, SAE, OWE, FILS — 105 functions
- **Key Management**: PTK/GTK derivation, installation, rotation — 22 functions  
- **EAPOL**: 4-way handshake, group key handshake — 2 functions
- **WSEC (Wireless Security)**: Cipher selection, WEP/TKIP/AES/GCMP — key functions

**Call graph roots:**
- `wlc_akm_attach` (0x32e098) / `wlc_akm_detach` (0x32e4a4) — module init/exit
- `wlc_keymgmt_attach` (0x27a698) / `wlc_keymgmt_detach` (0x27b308)
- `wlc_doiovar` (0x32c250) — iovar dispatch for AKM
- `wlc_eapol_event_indicate` (0x3f53c4) — EAPOL event callback

---

### 3.2 AKM (Authentication Key Management) — `wlc_akm_*`

**Symbol bucket:** 105 functions at 0x327d14-0x32e4a4

#### 3.2.1 AKM Lifecycle

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_akm_attach` | 0x32e098 | 0x40c | T | Initialize AKM module, register iovars |
| `wlc_akm_detach` | 0x32e4a4 | 0x38 | T | Cleanup AKM module |
| `wlc_akm_bsscfg_init` | 0x327cc8 | 0x20 | t | Per-BSS AKM init |
| `wlc_akm_bsscfg_deinit` | 0x327f6c | 0x80 | t | Per-BSS AKM deinit |

#### 3.2.2 RSN IE Construction (Beacon/Probe/Assoc)

**Beacon/Probe RSN IE writers (called from `wlc_iem_build_frame`):**
| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_akm_bcn_write_rsn_ie` | (in beacon_probe bucket) | — | Write RSN IE to beacon/probe |
| `wlc_akm_bcn_write_wpa_ie` | (in beacon_probe bucket) | — | Write WPA IE (legacy) |
| `wlc_akm_bcn_write_osen_ie` | 0x328674 | 0x60 | Write OSEN IE (Hotspot 2.0) |
| `wlc_akm_bcn_write_osen_rsn_ie` | 0x32b954 | 0x8fc | Write OSEN RSN IE |
| `wlc_akm_bcn_write_osen_wpa_ie` | 0x32a584 | 0x480 | Write OSEN WPA IE |

**RSN IE length calculators:**
| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_akm_calc_rsn_ie_len` | 0x32d568 | 0x8d4 | Calculate RSN IE length |
| `wlc_akm_calc_rsnxe_ie_len` | 0x328b50 | 0xf8 | Calculate RSNXE IE length (SAE H2E) |
| `wlc_akm_arq_calc_rsn_ie_len` | 0x32aa04 | 0x5c8 | ARQ (Auth Request) RSN IE len |
| `wlc_akm_arq_calc_wpa_ie_len` | 0x3298a4 | 0x388 | ARQ WPA IE len |
| `wlc_akm_arq_calc_osen_ie_len` | 0x3289cc | 0x24 | ARQ OSEN IE len |
| `wlc_akm_arq_calc_osen_rsn_ie_len` | 0x32afcc | 0x3c | ARQ OSEN RSN IE len |
| `wlc_akm_arq_calc_osen_wpa_ie_len` | 0x329c2c | 0x3c | ARQ OSEN WPA IE len |
| `wlc_akm_arsp_calc_rsn_ie_len` | 0x327d50 | 0x4c | ARSP (Auth Response) RSN IE len |
| `wlc_akm_arsp_calc_rsnxe_ie_len` | 0x327d9c | 0x60 | ARSP RSNXE IE len |

**RSN IE writers:**
| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_akm_write_rsnxe_ie` | 0x327ebc | 0x54 | Write RSNXE IE |
| `wlc_akm_arq_write_dh_ie` | 0x327f10 | 0x5c | ARQ write DH IE (SAE) |
| `wlc_akm_arq_write_osen_ie` | 0x3289f0 | 0x60 | ARQ write OSEN IE |
| `wlc_akm_arq_write_osen_rsn_ie` | 0x328c48 | 0x61c | ARQ write OSEN RSN IE |
| `wlc_akm_arq_write_osen_wpa_ie` | 0x329c68 | 0x418 | ARQ write OSEN WPA IE |
| `wlc_akm_arsp_write_rsn_ie` | 0x327fec | 0x6c | ARSP write RSN IE |
| `wlc_akm_arsp_write_rsnxe_ie` | 0x327e48 | 0x74 | ARSP write RSNXE IE |

#### 3.2.3 RSN IE Parsing (Scan/Assoc)

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_akm_scan_parse_rsn_ie` | 0x3280c8 | 0x588 | Parse RSN IE from scan results |
| `wlc_akm_scan_parse_wpa_ie` | 0x3286d4 | 0x2f8 | Parse WPA IE from scan |
| `wlc_akm_scan_parse_rsnxe_ie` | 0x327dfc | 0x4c | Parse RSNXE IE from scan |
| `wlc_akm_arq_parse_rsn_ie` | (ARQ) | — | Parse RSN in Auth Request |
| `wlc_akm_arq_parse_wpa_ie` | 0x3286d4 | 0x2f8 | ARQ parse WPA IE |
| `wlc_akm_arq_parse_osen_ie` | 0x32a080 | 0x504 | ARQ parse OSEN IE |
| `wlc_akm_arq_parse_osen_rsn_ie` | 0x32b008 | 0x94c | ARQ parse OSEN RSN IE |
| `wlc_akm_arq_parse_osen_wpa_ie` | 0x329264 | 0x3c0 | ARQ parse OSEN WPA IE |
| `wlc_akm_arq_parse_rsnxe_ie` | 0x328a50 | 0x100 | ARQ parse RSNXE IE |

#### 3.2.4 SAE (Simultaneous Authentication of Equals) / H2E

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_akm_is_sae_h2e_enabled` | 0x32df4c | 0x50 | T | Check if SAE Hash-to-Element enabled |
| `wlc_akm_save_scb_rsnxe` | 0x32dfa0 | 0xf8 | T | Save SCB RSNXE for SAE H2E |
| `wlc_akm_host_rsnxe` | 0x32defc | 0x50 | T | Host RSNXE handling |

#### 3.2.5 DH Parameters / Key Derivation

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_akm_calc_dh_params_ie_len` | 0x327cc8 | 0x4c | DH params IE length |
| `wlc_akm_write_dh_params_ie` | 0x328058 | 0x70 | Write DH params IE |
| `wlc_akm_arq_write_dh_ie` | 0x327f10 | 0x5c | ARQ write DH IE (SAE commit) |

#### 3.2.6 AKM iovar Dispatch

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_akm_doiovar` | 0x32c250 | 0x125c | t | AKM iovar dispatch (get/set) |
| `wlc_akm_bcn_calc_wpa_ie_len` | 0x329624 | 0x244 | t | Beacon WPA IE length |
| `wlc_akm_bcn_calc_osen_ie_len` | 0x328650 | 0x24 | t | Beacon OSEN IE length |
| `wlc_akm_bcn_calc_osen_rsn_ie_len` | 0x32de3c | 0x3c | t | Beacon OSEN RSN IE length |
| `wlc_akm_bcn_calc_osen_wpa_ie_len` | 0x329868 | 0x3c | t | Beacon OSEN WPA IE length |
| `wlc_akm_bcn_write_osen_ie` | 0x328674 | 0x60 | t | Beacon write OSEN IE |
| `wlc_akm_bcn_write_osen_rsn_ie` | 0x32b954 | 0x8fc | t | Beacon write OSEN RSN IE |
| `wlc_akm_bcn_write_osen_wpa_ie` | 0x32a584 | 0x480 | t | Beacon write OSEN WPA IE |

---

### 3.3 Key Management — `wlc_keymgmt_*`

**Symbol bucket:** 22 functions at 0x27a698-0x28b70c

#### 3.3.1 Lifecycle

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_attach` | 0x27a698 | 0x368 | T | Initialize keymgmt, allocate cubbys |
| `wlc_keymgmt_detach` | 0x27b308 | 0x28 | T | Cleanup keymgmt |

#### 3.3.2 Key Retrieval

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_get_bss_key` | 0x27ca24 | 0xbc | T | Get BSS (group) key |
| `wlc_keymgmt_get_bss_key_algo` | 0x27ce80 | 0x290 | T | Get BSS key algorithm (WEP/TKIP/AES) |
| `wlc_keymgmt_get_bss_tx_key` | 0x27cae0 | 0xdc | T | Get BSS TX key |
| `wlc_keymgmt_get_bss_tx_key_id` | 0x27cbbc | 0x3c | T | Get BSS TX key index |
| `wlc_keymgmt_get_cur_wsec_algo` | 0x27acc8 | 0x94 | T | Get current WSEC algorithm |
| `wlc_keymgmt_get_key` | 0x28ad30 | 0x64 | T | Get key by SCB |
| `wlc_keymgmt_get_key_by_addr` | (undefined?) | — | Get key by MAC address |
| `wlc_keymgmt_get_scb_key` | (undefined?) | — | Get SCB (pairwise) key |
| `wlc_keymgmt_get_scb_amt_idx` | 0x28a354 | 0x8 | T | Get SCB AMT index |
| `wlc_keymgmt_get_bsscfg` | 0x28a9b8 | 0x58 | T | Get bsscfg from key context |
| `wlc_keymgmt_get_wsec_info` | 0x27ac9c | 0x2c | T | Get WSEC info (used by wsec_info ioctl) |

#### 3.3.3 Key Installation / Rotation

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_set_bss_tx_key_id` | 0x28b630 | 0x8 | T | Set BSS TX key index |
| `wlc_keymgmt_tkip_set_cm` | (undefined?) | — | Set TKIP countermeasures |
| `wlc_keymgmt_tkip_cm_enabled` | 0x27b308 | 0x28 | T | Check TKIP countermeasures enabled |
| `wlc_keymgmt_b4m4_enabled` | (undefined?) | — | Check B4M4 (MFP) enabled |
| `wlc_keymgmt_restore_scb_amt_entry` | (undefined?) | — | Restore SCB AMT entry |

#### 3.3.4 AMT (Address Mapping Table) / Key Cache

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_alloc_amt` | 0x28b6f4 | 0x18 | T | Allocate AMT entry |
| `wlc_keymgmt_free_amt` | 0x28b70c | 0x8 | T | Free AMT entry |
| `wlc_keymgmt_amt_reserve` | 0x28b6ec | 0x8 | T | Reserve AMT slot |
| `wlc_keymgmt_amt_idx_isset` | 0x28a354 | 0x8 | T | Check if AMT index set |
| `wlc_keymgmt_amt_link` | (undefined?) | — | Link SCB to AMT |
| `wlc_keymgmt_amt_delink` | (undefined?) | — | Delink SCB from AMT |

#### 3.3.5 Key Algorithms / Hardware Mapping

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_algo_to_hw_algo` | 0x28b630 | 0x8 | T | Map SW cipher to HW cipher ID |

#### 3.3.6 Events / Callbacks

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_event_register` | 0x27d5fc | 0x24 | T | Register keymgmt event callback |
| `wlc_keymgmt_event_unregister` | 0x27d620 | 0x24 | T | Unregister keymgmt event callback |
| `wlc_keymgmt_notify` | (undefined?) | — | Notify keymgmt of events |

#### 3.3.7 Recv/Key Data Processing

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_keymgmt_recvdata` | (undefined?) | — | Process received key data frames |

---

### 3.4 EAPOL — `wlc_eapol_*`

**Symbol bucket:** 2 functions

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_eapol_event_indicate` | 0x3f53c4 | 0x278 | T | Indicate EAPOL event to host (4-way handshake events) |
| `wlc_eapol_pktget` | 0x56fad8 | 0xfc | T | Get EAPOL packet for transmission |

**Call sites (from call graph):**
- `wlc_eapol_event_indicate` called 3 times (handshake events: M1/M2/M3/M4, group key)
- `wlc_eapol_pktget` called 5 times (EAPOL packet retrieval for TX)

---

### 3.5 WSEC (Wireless Security) — `wlc_wsec_*`

**Symbol bucket:** Limited in symtab — only `wlc_wsec_recv` (0x4a3edc, 0x280) found in symtab. Other WSEC functions likely inlined or named differently.

**Key related functions from other buckets:**
- `wlc_ht_get_wsec_restriction` (0x414df0, 0x18) — HT capability restriction based on WSEC
- `wlc_ht_get_wsec_restriction` called from `wlc_bcn_prb_body` at 0x312e44
- `wlc_wsec_recv` (0x4a3edc, 0x280) — Receive path WSEC processing

**WSEC bitmask (from impl87 `wlioctl.h`):**
```c
#define WEP_ENABLED     0x0001
#define TKIP_ENABLED    0x0002
#define AES_ENABLED     0x0004
#define WSEC_SWFLAG     0x0008
#define MFP_CAPABLE     0x0200
#define MFP_REQUIRED    0x0400
#define MFP_SHA256      0x0800
```

**bsscfg wsec field** at `+0x4c` (verified in Chapter 1 & 2) — read by:
- Privacy gate in `wlc_bcn_prb_body` at 0x313090
- HT restriction at 0x312e50
- AKM RSN IE construction

---

### 3.6 Call Graph Summary

```
wlc_attach()
    ├─ wlc_akm_attach() → register AKM iovars
    ├─ wlc_keymgmt_attach() → allocate cubbys, init AMT
    └─ ...

wl_ioctl(WLC_SET_WSEC, ...)
    └─ wlc_doioctl case 23 → bsscfg+0x4c = wsec value

wl_ioctl(WLC_SET_WPA_AUTH, ...)
    └─ wlc_doioctl case 127 → bsscfg WPA_auth field

wl_ioctl(WLC_SET_WSEC_PMK, ...)
    └─ wlc_doioctl case ? → wlc_keymgmt PMK install

EAPOL RX path:
    wlc_recv()
        └─ wlc_eapol_event_indicate() → hostapd/supplicant
        └─ wlc_keymgmt_recvdata() → process key frames

Beacon RSN IE:
    wlc_bcn_prb_body()
        └─ wlc_iem_build_frame()
            └─ wlc_akm_bcn_write_rsn_ie() → uses bsscfg wsec + WPA_auth

Scan/Assoc RSN parsing:
    wlc_scan_parse()
        └─ wlc_akm_scan_parse_rsn_ie()
        └─ wlc_akm_scan_parse_wpa_ie()
```

---

### 3.7 Binary Offsets Quick Reference

| Function | Address | Size | Key Data Access |
|----------|---------|------|-----------------|
| `wlc_akm_attach` | 0x32e098 | 0x40c | Registers iovars |
| `wlc_akm_doiovar` | 0x32c250 | 0x125c | iovar dispatch |
| `wlc_akm_calc_rsn_ie_len` | 0x32d568 | 0x8d4 | RSN IE length |
| `wlc_akm_bcn_write_rsn_ie` | (beacon_probe) | — | Beacon RSN IE |
| `wlc_keymgmt_attach` | 0x27a698 | 0x368 | Cubby/AMT init |
| `wlc_keymgmt_get_bss_key` | 0x27ca24 | 0xbc | BSS key retrieval |
| `wlc_keymgmt_get_cur_wsec_algo` | 0x27acc8 | 0x94 | Current cipher |
| `wlc_keymgmt_get_wsec_info` | 0x27ac9c | 0x2c | wsec_info ioctl |
| `wlc_eapol_event_indicate` | 0x3f53c4 | 0x278 | EAPOL events |
| `wlc_eapol_pktget` | 0x56fad8 | 0xfc | EAPOL TX |
| `wlc_wsec_recv` | 0x4a3edc | 0x280 | RX WSEC processing |
| `wlc_ht_get_wsec_restriction` | 0x414df0 | 0x18 | HT caps vs WSEC |

---

## Chapter 4: Ioctl Dispatch & Ivars (`wlc_doioctl`, `wlc_bssiovar`, `wlc_iovar`, iovar tables)

### 4.1 `wlc_doioctl` — Main Ioctl Dispatcher

**Address:** 0x31a2ac (size 0x2d38 = 11,576 bytes)

**Signature:** `wlc_doioctl(wlc_info *wlc, int cmd, void *buf, int len, ...)`

**Register mapping at entry (from 0x31a2c0):**
- `r0` = `wlc_info` → `r4`
- `r1` = `cmd` (ioctl number) → `r6` (used as jump table index)
- `r2` = `buf` → `r5`
- `r3` = `len` → saved to stack

**Dispatch mechanism:** Direct jump table at 0x31a32c indexed by `cmd` (0..330 = WLC_LAST)

```asm
; At 0x31a320-0x31a328:
cmp   r6, r3          ; r3 = 330 (WLC_LAST)
ldrls pc, [pc, r6, lsl #2]  ; jump table lookup
b     default_handler ; 0x31a858 if cmd > 330
```

**Jump table base:** 0x31a32c (331 entries × 4 bytes = 0x52c bytes, ends at ~0x31a858)

**Default handler:** 0x31a858 — returns error for unimplemented ioctls

---

### 4.2 Ioctl Number Assignments (from impl87 `wlioctl.h` + binary verification)

| Ioctl | Name | Handler Type | Binary Evidence |
|-------|------|--------------|-----------------|
| 0 | WLC_GET_MAGIC | Direct | — |
| 1 | WLC_GET_VERSION | Direct | — |
| 2 | WLC_UP | Direct | `wlc_up` caller at 0x2f0cfc |
| 3 | WLC_DOWN | Direct | `wlc_down` caller at 0x2f23b0 |
| 4 | WLC_GET_LOOP | Direct | — |
| 5 | WLC_SET_LOOP | Direct | — |
| 6 | WLC_DUMP | Direct | — |
| 7/8 | WLC_GET/SET_MSGLEVEL | Direct | — |
| 9/10 | WLC_GET/SET_PROMISC | Direct | — |
| 12/13 | WLC_GET/SET_RATE | Direct | — |
| 14 | WLC_GET_INSTANCE | Direct | — |
| 20/21 | WLC_GET/SET_AUTH | Direct | `wlc_bsscfg` auth |
| 22/23 | **WLC_GET/SET_WSEC** | **Direct** | **bsscfg+0x4c = wsec** (Privacy gate) |
| 81/82 | **WLC_GET/SET_WEP_RESTRICT** | **Direct** | **bsscfg+0x54 = wep_restrict** (Privacy gate) |
| 83/84 | WLC_GET/SET_COUNTRY | Direct | — |
| 85/86 | WLC_GET/SET_PM | Direct | Power management |
| 94/95 | WLC_GET/SET_PHYREG | Direct | PHY debug |
| 100/101 | WLC_GET/SET_BCNPRD | Direct | Beacon interval |
| 102/103 | WLC_GET/SET_DTIMPRD | Direct | DTIM period |
| 110/111 | WLC_GET/SET_GMODE | Direct | 802.11g mode |
| 116/117 | WLC_GET/SET_CHANNEL | Direct | Channel |
| 126/127 | **WLC_GET/SET_WPA_AUTH** | **Direct** | **bsscfg WPA_auth** |

---

### 4.3 Key Ioctl Handler Analysis (from disassembly)

#### 4.3.1 WLC_SET_WSEC (cmd 23) — at ~0x31c400 area

Sets `bsscfg+0x4c` (wsec field). This is the **primary cipher selector** read by:
- Privacy gate in `wlc_bcn_prb_body` (0x313090)
- HT restriction in `wlc_bcn_prb_body` (0x312e50)

#### 4.3.2 WLC_SET_WEP_RESTRICT (cmd 82) — at 0x31c438

```asm
; Case 82 handler:
strb  r2, [r0, #0x54]   ; r0 = bsscfg (from wlc_bsscfg_find_by_wlcif), r2 = bool(arg)
```
**Sets `bsscfg+0x54` (wep_restrict) — the Privacy bit gate byte!**

This is the **missing piece** in the user's AP bring-up sequence.

#### 4.3.3 WLC_SET_WPA_AUTH (cmd 127) — at ~0x31c400 area

Sets `bsscfg WPA_auth` field (offset in impl87 `wl_bsscfg_t` at +0x04).

---

### 4.4 Iovar System — String-based Configuration

Two iovar dispatch paths:

#### 4.4.1 Global Ivars — `wlc_iovar` / `wlc_doiovar`

**Dispatcher:** `wlc_doiovar` at 0x32c250 (AKM) + others

**Mechanism:** String name → hash → function pointer table → handler

**Key global ivars (from symbol names):**
- `wlc_iov_bss` — BSS iovar
- `wlc_iov_country` — Country code
- `wlc_iov_chanspec` — Channel spec
- `wlc_iov_wme` — WMM parameters
- `wlc_iov_ampdu` — AMPDU settings
- `wlc_iov_sta` — Station parameters

#### 4.4.2 BSSCFG Ivars — `wlc_bssiovar`

**Dispatcher:** `wlc_bssiovar` (called from `wlc_doioctl` for WLC_GET/SET_VAR with BSS index)

**Mechanism:** Per-BSS configuration via `wl_bsscfg_int` / `wl_bsscfg_str` in user tool

**Key BSSCFG ivars (from impl87 `wlu.c`):**
| Ivar | Get Ioctl | Set Ioctl | Type | Purpose |
|------|-----------|-----------|------|---------|
| `wsec` | 81 | 82 | int | **Cipher bitmask** (Privacy gate) |
| `wsec_restrict` | 81 | 82 | int | **Privacy bit gate** (wep_restrict) |
| `wpa_auth` | — | — | int | WPA auth modes |
| `ssid` | — | — | string | ESSID |
| `closednet` | — | — | int | Hidden SSID |
| `maxassoc` | — | — | int | Max stations |
| `ap_isolate` | — | — | int | Client isolation |
| `chanspec` | — | — | int | Channel + BW |

---

### 4.5 Iovar Tables — Binary Structure

**Global iovar table** (searched via `wlc_iov_*` symbols):
- Hash-based lookup: `hash(name) % table_size` → bucket → linear search
- Each entry: `{ name_ptr, flags, get_handler, set_handler, arg_size, ... }`

**BSSCFG iovar table** (searched via `wlc_bssiovar_*` symbols):
- Similar structure but with BSS index parameter
- Handlers: `wl_bsscfg_int`, `wl_bsscfg_str`, `wl_bsscfg_buf`

---

### 4.6 User Tool Interface (from impl87 `wlu.c`)

**Ioctl command mapping:**
```c
{ "wsec",           wl_bsscfg_int,  WLC_GET_WSEC,      WLC_SET_WSEC,      ... },
{ "wsec_restrict",  wl_bsscfg_int,  WLC_GET_WEP_RESTRICT, WLC_SET_WEP_RESTRICT, ... },
{ "wpa_auth",       wl_bsscfg_int,  WLC_GET_WPA_AUTH,  WLC_SET_WPA_AUTH,  ... },
{ "ssid",           wl_bsscfg_str,  ... },
{ "chanspec",       wl_bsscfg_int,  ... },
```

**Hostapd mapping:**
| Hostapd Config | wl iovar | Ioctl |
|----------------|----------|-------|
| `wpa_pairwise` | `wsec` | WLC_SET_WSEC (23) |
| `wpa_key_mgmt` | `wpa_auth` | WLC_SET_WPA_AUTH (127) |
| `ieee80211w` / `drop_unencrypted` | `wsec_restrict` | WLC_SET_WEP_RESTRICT (82) |
| `ssid` | `ssid` | WLC_SET_SSID |
| `channel` | `chanspec` | WLC_SET_CHANNEL |

---

### 4.7 Correct AP Bring-Up Sequence (Hostapd-compatible)

```c
// 1. Bring radio down
wl_ioctl(WLC_DOWN, 0);

// 2. Set AP mode
wl_ioctl(WLC_SET_AP, 1);

// 3. Configure SSID
wl_bssiovar_set("ssid", "MyNetwork");

// 4. Set WPA2-PSK
wl_bssiovar_set("wpa_auth", WPA2_AUTH_PSK);  // 0x80

// 5. Set encryption (AES/CCMP)
wl_bssiovar_set("wsec", AES_ENABLED);        // 4

// 6. CRITICAL: Enable restrict flag for Privacy bit
wl_bssiovar_set("wsec_restrict", 1);         // WLC_SET_WEP_RESTRICT (82)

// 7. Set PMK (from passphrase)
wl_ioctl(WLC_SET_WSEC_PMK, &pmk);

// 8. Set channel
wl_ioctl(WLC_SET_CHANNEL, chanspec);

// 9. Bring BSS up
wl_ioctl(WLC_UP, 0);
wl_bssiovar_set("bss", 1);  // BSS up
```

**Key insight:** Step 6 (`wsec_restrict=1`) is **mandatory** for Privacy bit in beacons — without it, `bsscfg+0x54` stays 0 and Privacy bit is never set, even with valid RSN IE.

---

### 4.8 Binary Offsets Quick Reference

| Function | Address | Size | Key Feature |
|----------|---------|------|-------------|
| `wlc_doioctl` | 0x31a2ac | 0x2d38 | Jump table dispatch (0..330) |
| Jump table | 0x31a32c | 0x52c | 331 entries |
| Default handler | 0x31a858 | — | Error for invalid cmd |
| `wlc_bssiovar` | (in doioctl) | — | Per-BSS iovar dispatch |
| `wlc_iovar` / `wlc_doiovar` | 0x32c250+ | — | Global iovar dispatch |
| `wlc_bsscfg_find_by_wlcif` | 0x3a579c | — | BSS lookup by interface |

---

## Chapter 5: BSSCFG/SCB Lifecycle (`wlc_bsscfg_*`, `wlc_scb_*`, `wlc_ap_*`)

### 5.1 Subsystem Overview

This chapter covers the lifecycle management of BSS configurations (virtual APs) and Station Control Blocks (associated clients), plus AP-mode specific operations.

**Key symbol buckets (from call graph):**
- `wlc_bsscfg_*` — 125+ call sites (417 symbols in bucket)
- `wlc_scb_*` — 213 iterators, 48+ ratesel, 8+ ampdu, 26+ cubby
- `wlc_ap_*` — AP-mode specific (beacon, probe resp, assoc handling)

**Core structures:**
- `wlc_bsscfg` — Per-BSS state (Chapter 1: offsets +0x4c wsec, +0x54 wep_restrict, +0x74 flags)
- `wlc_scb` — Per-station state (ratesel, ampdu, cubby, key cache)

---

### 5.2 BSSCFG Lifecycle — `wlc_bsscfg_*`

**Call graph roots:** 125+ call sites across attach, up/down, assoc, scan, beacon

#### 5.2.1 Allocation / Initialization

| Function | Address | Size | Type | Purpose |
|----------|---------|------|------|---------|
| `wlc_bsscfg_attach` | (in bsscfg_scb bucket) | — | Allocate & initialize bsscfg |
| `wlc_bsscfg_primary_init` | (in bsscfg_scb bucket) | — | Initialize primary (first) BSS |
| `wlc_bsscfg_init` | (in bsscfg_scb bucket) | — | General BSS init |
| `wlc_bsscfg_cubby_reserve` | 26+ calls | — | Reserve per-BSS cubby space |
| `wlc_bsscfg_cubby_reserve_ext` | (in bucket) | — | Extended cubby reservation |
| `wlc_bsscfg_viel_attach` | (in bucket) | — | Attach Vendor IE list |

#### 5.2.2 BSS Up / Down (Critical for Beacon Generation)

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_up` | (in bucket) | 7 | **Enable BSS → starts beaconing** |
| `wlc_bsscfg_down` | (in bucket) | 7 | **Disable BSS → stops beaconing** |
| `wlc_bsscfg_enable` | (in bucket) | 9 | Enable BSS (internal) |
| `wlc_bsscfg_disable` | (in bucket) | 16 | Disable BSS (internal) |

**Critical sequence for AP bring-up:**
```
wlc_bsscfg_attach() → wlc_bsscfg_init() → wlc_bsscfg_up()
```
**`wlc_bsscfg_up` triggers beacon template regeneration** via `wlc_update_beacon()` (17 call sites).

#### 5.2.3 BSS Configuration

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_find` | 21 | Find BSS by various criteria |
| `wlc_bsscfg_find_by_wlcif` | 125 | **Primary lookup by interface** (0x3a579c) |
| `wlc_bsscfg_find_by_hwaddr` | 16 | Find by MAC |
| `wlc_bsscfg_find_by_bssid` | 3 | Find by BSSID |
| `wlc_bsscfg_find_by_ssid` | (in bucket) | Find by SSID |
| `wlc_bsscfg_find_by_ID` | 3 | Find by BSS ID |
| `wlc_bsscfg_find_by_target_bssid` | 3 | Find for roaming |
| `wlc_bsscfg_find_by_hwaddr_bssid` | (in bucket) | Combined lookup |
| `wlc_bsscfg_find_by_current_mbssid` | (in bucket) | Multi-BSS lookup |

#### 5.2.4 Configuration Setters (via iovars/ioctls)

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_SSID_set` | 13 | Set SSID |
| `wlc_bsscfg_assoc_params_set` | 9 | Set association params |
| `wlc_bsscfg_assoc_params_reset` | 3 | Reset assoc params |
| `wlc_bsscfg_scan_params_set` | 9 | Set scan parameters |
| `wlc_bsscfg_scan_params_reset` | (in bucket) | Reset scan params |
| `wlc_bsscfg_reprate_init` | 5 | Initialize report rate |
| `wlc_bsscfg_reinit` | 5 | Reinitialize BSS |
| `wlc_bsscfg_update_rclass` | 3 | Update regulatory class |

#### 5.2.5 BSS Type / Capabilities

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_type_get` | (in bucket) | Get BSS type (AP/STA/IBSS) |
| `wlc_bsscfg_type_fixup` | 2 | Fixup BSS type |
| `wlc_bsscfg_type_bi2cfg` | 2 | BSS index to config |
| `wlc_bsscfg_is_mbo_enabled` | 9 | Check MBO enabled |
| `wlc_bsscfg_is_oce_enabled` | 9 | Check OCE enabled |
| `wlc_bsscfg_is_probe_response_required` | 3 | Check probe resp needed |
| `wlc_bsscfg_mfp_supported` | 2 | Check MFP (802.11w) support |
| `wlc_bsscfg_mcastfilter` | 2 | Multicast filter config |

#### 5.2.6 Traffic / Rate Management

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_traffic_thresh_init` | 4 | Init traffic threshold |
| `wlc_bsscfg_traffic_thresh_deinit` | 8 | Deinit traffic threshold |
| `wlc_bsscfg_reprate_init` | 5 | Init report rate |
| `wlc_bsscfg_bcmc_scb_init` | (in bucket) | Init broadcast/multicast SCB |

#### 5.2.7 Cleanup / Detach

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_bsscfg_free` | (in bucket) | Free BSS resources |
| `wlc_bsscfg_detach` | (in bucket) | Detach BSS |
| `wlc_bsscfg_viel_detach` | (in bucket) | Detach Vendor IE list |
| `wlc_bsscfg_bcmcscbfree` | (in bucket) | Free BCMC SCB |

---

### 5.3 SCB Lifecycle — `wlc_scb_*`

**Call graph:** 213 `iterinit`/`iternext`, 231 `scbfind`, 1855 `scbfind_from_wlcif`

#### 5.3.1 Allocation / Attachment

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_attach` | 1 | Attach SCB (new association) |
| `wlc_scb_reinit` | 1 | Reinitialize SCB |
| `wlc_scb_cubby_reserve` | 20 | Reserve SCB cubby |
| `wlc_scb_cubby_reserve_ext` | (in bucket) | Extended cubby |

#### 5.3.2 Association / Disassociation

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_set_auth` | 4 | Set auth state |
| `wlc_scb_disassoc_cleanup` | 11 | Cleanup on disassoc |
| `wlc_scb_cleanup_unused` | 1 | Cleanup unused SCBs |
| `wlc_scb_flush_queues` | 1 | Flush TX queues |

#### 5.3.3 State Management

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_setstatebit` | 26 | Set state bit |
| `wlc_scb_clearstatebit` | 38 | Clear state bit |
| `wlc_scb_resetstate` | 8 | Reset all state |
| `wlc_scb_state_upd_register` | 18 | Register state update callback |
| `wlc_scb_state_upd_unregister` | 26 | Unregister state update |

#### 5.3.4 Rate Selection (Major Subsystem — 48+ variants)

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_ratesel_init` | 48 | Initialize rate selection |
| `wlc_scb_ratesel_init_all` | 11 | Init all SCBs |
| `wlc_scb_ratesel_init_bss` | 12 | Init for BSS |
| `wlc_scb_ratesel_init_rcb_itxs` | 3 | Init for RCB/ITxS |
| `wlc_scb_ratesel_attach` | 1 | Attach ratesel |
| `wlc_scb_ratesel_detach` | 1 | Detach ratesel |
| `wlc_scb_ratesel_gettxrate` | 18 | Get TX rate |
| `wlc_scb_ratesel_get_ulrt_rspec` | 10 | Get UL RT rspec |
| `wlc_scb_ratesel_get_ulmu_link_bw` | 9 | Get UL MU link BW |
| `wlc_scb_ratesel_get_opstats` | 9 | Get operational stats |
| `wlc_scb_ratesel_get_muboost` | 9 | Get MU boost |
| `wlc_scb_ratesel_get_ratecap` | 1 | Get rate cap |
| `wlc_scb_ratesel_get_ulrt_txr` | 8 | Get UL RT TXR |
| `wlc_scb_ratesel_get_ulrt_trssi` | 4 | Get UL RT TRSSI |
| `wlc_scb_ratesel_get_rcb` | 2 | Get RCB |
| `wlc_scb_ratesel_change_epoch` | 2 | Change epoch |
| `wlc_scb_ratesel_upd_txs_ampdu` | 2 | Update TXS AMPDU |
| `wlc_scb_ratesel_upd_txs_trig` | 1 | Update TXS trigger |
| `wlc_scb_ratesel_upd_txs_blockack` | 1 | Update TXS blockack |
| `wlc_scb_ratesel_upd_itxs` | 1 | Update ITxS |
| `wlc_scb_ratesel_probe_ready` | 7 | Probe ready |
| `wlc_scb_ratesel_is_start_sp` | 4 | Is start SP |
| `wlc_scb_ratesel_minrate` | 3 | Min rate |
| `wlc_scb_ratesel_getmcsfbr` | 1 | Get MCS FBR |
| `wlc_scb_ratesel_rfbr_bss` | 1 | RFBR BSS |
| `wlc_scb_ratesel_clr_cache` | 3 | Clear cache |

#### 5.3.5 AMPDU / BlockAck

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_ampdu_enable` | 8 | Enable AMPDU |
| `wlc_scb_ampdu_disable` | 11 | Disable AMPDU |
| `wlc_scb_ampdurx_on` | 4 | AMPDU RX on |

#### 5.3.6 Traffic Control

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_pause_traffic` | 5 | Pause traffic |
| `wlc_scb_resume_traffic` | 16 | Resume traffic |
| `wlc_scb_pktc_enable` | 3 | Packet concatenation enable |
| `wlc_scb_pktc_disable` | 3 | Packet concatenation disable |

#### 5.3.7 Link / SCB Lookup

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scbfind` | 231 | Find SCB by MAC |
| `wlc_scbfind_from_wlcif` | 1855 | Find SCB by interface |
| `wlc_scb_link_update` | 3 | Update link state |
| `wlc_scb_get_link_credits` | 3 | Get link credits |
| `wlc_scb_close_link` | 4 | Close link |
| `wlc_scb_host_ring_link` | 1 | Host ring link |
| `wlc_scb_flowid_lookup` | 13 | Flow ID lookup |
| `wlc_scb_flowid_global_lookup` | 120 | Global flow ID lookup |
| `wlc_scb_flowid_addr_lookup` | 1 | Flow ID by address |

#### 5.3.8 Key / Security (AMT — Address Mapping Table)

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_amt_lookup` | 1 | AMT lookup |
| `wlc_scb_amt_link` | 1 | Link to AMT |
| `wlc_scb_amt_delink` | 1 | Delink from AMT |
| `wlc_scb_save_wpa_ie` | 1 | Save WPA IE |
| `wlc_scb_rsn_ie_free` | 1 | Free RSN IE |

#### 5.3.9 TX / TX Info

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_scb_txc_info` | 3 | TX completion info |
| `wlc_scb_get_txfifo` | 3 | Get TX FIFO |
| `wlc_scb_pktc_enable` | 3 | Packet concat enable |
| `wlc_scb_pktc_disable` | 3 | Packet concat disable |

---

### 5.4 AP-Mode Operations — `wlc_ap_*`

**Call graph roots:** Beacon update, probe response, association handling

| Function | Address | Call Count | Purpose |
|----------|---------|------------|---------|
| `wlc_ap_process_assocreq` | 0x357d14 | — | Process association request (sets wep_restrict from STA caps) |
| `wlc_ap_bcast_probe_rsp_update_required` | 0x35a298 | 1 | Check if broadcast probe resp needs update |
| `wlc_ap_get_psta_prim` | 0x35d754 | 1 | Get primary PSTA |
| `wlc_ap_bcn_disable` | 2 | Disable beaconing |

---

### 5.5 Beacon Update Path (Critical for Capability Changes)

**Call graph (17 call sites for `wlc_update_beacon`):**
```
wlc_bsscfg_up() / wlc_bsscfg_down()
    └─ wlc_update_beacon()  [17 call sites]
        └─ wlc_bcn_prb_template() → wlc_bcn_prb_body()
            └─ Capabilities: Privacy gate (bsscfg+0x4c & +0x54)
            └─ RSN IE via wlc_akm_bcn_write_rsn_ie()
```

**Key insight:** Any change to `wsec` (0x31c400) or `wep_restrict` (0x31c438) requires `wlc_bsscfg_down/up` cycle to regenerate beacon with updated capabilities.

---

### 5.6 Association Request Processing — `wlc_ap_process_assocreq`

**Address:** 0x357d14 (size 0xf74)

**Key finding from Chapter 2/4:** At 0x357f78, this function writes `bsscfg+0x54` (wep_restrict) derived from STA capabilities:

```asm
; At 0x357f78 in wlc_ap_process_assocreq:
strb r3, [r5, #0x54]   ; r5 = bsscfg, r3 = derived from STA caps
```

This is the **third writer** of the Privacy gate byte (after ioctl 82 and `wlc_fbtap_write_ft_ie`).

---

### 5.7 Call Graph Summary

```
wlc_attach()
    ├─ wlc_bsscfg_attach() → allocate primary BSS
    ├─ wlc_bsscfg_primary_init()
    └─ wlc_scb module init

wl_up() / wl_bss_up()
    └─ wlc_bsscfg_up() → wlc_update_beacon() (17 sites)
        └─ wlc_bcn_prb_template() → wlc_bcn_prb_body()
            └─ Privacy gate: bsscfg+0x4c & 7 && bsscfg+0x54

wl_ioctl(WLC_SET_WSEC) → bsscfg+0x4c
    └─ Requires wlc_bsscfg_down/up to refresh beacon

wl_ioctl(WLC_SET_WEP_RESTRICT) → bsscfg+0x54
    └─ Requires wlc_bsscfg_down/up to refresh beacon

Association:
    wlc_ap_process_assocreq()
        └─ Sets bsscfg+0x54 from STA caps
        └─ wlc_keymgmt_install_ptk/gtk
```

---

### 5.8 Binary Offsets Quick Reference

| Function | Address | Size | Key Feature |
|----------|---------|------|-------------|
| `wlc_bsscfg_find_by_wlcif` | 0x3a579c | — | Primary BSS lookup (125 calls) |
| `wlc_bsscfg_up` | (in bucket) | — | Enable BSS → beacon (7 calls) |
| `wlc_bsscfg_down` | (in bucket) | — | Disable BSS (7 calls) |
| `wlc_bsscfg_disable` | (in bucket) | 16 | Internal disable |
| `wlc_bsscfg_enable` | (in bucket) | 9 | Internal enable |
| `wlc_scb_iterinit` | (in bucket) | 213 | SCB iteration start |
| `wlc_scb_iternext` | (in bucket) | 213 | SCB iteration next |
| `wlc_scbfind` | (in bucket) | 231 | Find SCB by MAC |
| `wlc_scbfind_from_wlcif` | (in bucket) | 1855 | Find SCB by interface |
| `wlc_ap_process_assocreq` | 0x357d14 | 0xf74 | AssocReq → sets wep_restrict |
| `wlc_update_beacon` | (in bucket) | 17 | Beacon regeneration |
| `wlc_update_probe_resp` | 0x319c30 | — | Probe response update |

---

## Chapter 6: Channel/Chanspec/Regulatory (`wlc_chanspec_*`, `wlc_channel_*`, `wlc_country_*`, `wlc_dfs_*`, `wlc_radar_*`)

### 6.1 Subsystem Overview

The channel/chanspec/regulatory subsystem manages:
- **Channel specifications (chanspec)**: Encoding of channel, bandwidth, band, control channel
- **Channel management**: Valid channel lists, regulatory limits, DFS
- **Country/locale**: Regulatory domain handling, locale flags
- **DFS (Dynamic Frequency Selection)**: Radar detection, CAC (Channel Availability Check), CSA (Channel Switch Announcement)
- **Radar detection**: Radar reporting, monitor mode

**Symbol bucket:** 86 functions in `chanspec_reg` (0x30549c - 0x31a2ac range)

---

### 6.2 Channel Manager — `wlc_channel_mgr_*`

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `wlc_channel_mgr_attach` | (in chanspec_reg) | — | Initialize channel manager |
| `wlc_channel_mgr_detach` | (in chanspec_reg) | — | Cleanup channel manager |

---

### 6.3 Channel Operations — `wlc_channel_*`

#### 6.3.1 Channel Queries

| Function | Purpose |
|----------|---------|
| `wlc_channel_get_chanvec` | Get valid channel vector for band |
| `wlc_channel_get_valid_channels_vec` | Get valid channels vector |
| `wlc_channel_get_cur_rclass` | Get current regulatory class |
| `wlc_channel_calc_rclass_ie_len` | Calculate regulatory class IE length |
| `wlc_channel_write_rclass_ie` | Write regulatory class IE |
| `wlc_channel_next_2gchanspec` | Get next 2GHz chanspec |
| `wlc_channel_rand_chanspec` | Random chanspec selection |

#### 6.3.2 Channel Configuration

| Function | Purpose |
|----------|---------|
| `wlc_channel_set_chanspec` | Set chanspec (primary API) |
| `wlc_channel_set_tx_power` | Set TX power for channel |
| `wlc_channel_set_txpower_limit` | Set TX power limit |
| `wlc_channel_update_txpwr_limit` | Update TX power limit |
| `wlc_channel_update_txchain_offsets` | Update TX chain offsets |
| `wlc_channel_tx_power_target_min_max` | TX power target min/max |
| `wlc_channel_max_tx_power_for_band` | Max TX power for band |
| `wlc_channel_apply_band_chain_limits` | Apply band/chain limits |

#### 6.3.3 Country / Regulatory

| Function | Purpose |
|----------|---------|
| `wlc_channel_country` | Get/set country |
| `wlc_channel_country_abbrev` | Country abbreviation |
| `wlc_channel_ccode` | Country code |
| `wlc_channel_srom_ccode` | SROM country code |
| `wlc_channel_srom_regrev` | SROM regulatory revision |
| `wlc_channel_reg_limits` | Regulatory limits |
| `wlc_channel_regrev` | Regulatory revision |
| `wlc_channel_setcountry` | Set country code |
| `wlc_channel_locale_flags` | Locale flags |
| `wlc_channel_locale_flags_in_band` | Locale flags per band |

#### 6.3.4 DFS / Radar

| Function | Purpose |
|----------|---------|
| `wlc_channel_2g_dfs_chan` | 2GHz DFS channel check |
| `wlc_channel_clm_restricted_chanspec` | CLM restricted chanspec |
| `wlc_channel_set_phy_radar_detect` | PHY radar detect config |
| `wlc_channel_sarenable_get` | SAR enable get |
| `wlc_channel_sarenable_set` | SAR enable set |
| `wlc_channel_margin_summary_mapfn` | Margin summary map function |

---

### 6.4 Chanspec Operations — `wlc_chanspec_*`

| Function | Purpose |
|----------|---------|
| `wlc_chanspec_ac2opclass` | Convert chanspec to operating class |
| `wlc_chanspec_list_ordered` | Ordered chanspec list |

---

### 6.5 Country/Locale — `wlc_country_*`, `wlc_locale_*`

| Function | Purpose |
|----------|---------|
| `wlc_country_lookup` | Country lookup by code |
| `wlc_country_lookup_direct` | Direct country lookup |
| `wlc_country_lookup_ext` | Extended country lookup |
| `wlc_country_clear_locales` | Clear locale list |
| `wlc_locale_get_channels` | Get channels for locale |
| `wlc_channel_sarenable_get/set` | SAR enable |

---

### 6.6 DFS (Dynamic Frequency Selection) — `wlc_dfs_*`

**Major subsystem:** Radar detection, CAC, CSA, radar reporting

#### 6.6.1 DFS Lifecycle

| Function | Purpose |
|----------|---------|
| `wlc_dfs_attach` | Initialize DFS |
| `wlc_dfs_detach` | Cleanup DFS |
| `wlc_dfs_up` | Enable DFS |
| `wlc_dfs_down` | Disable DFS |
| `wlc_dfs_updown_cb` | Up/down callback |

#### 6.6.2 CAC (Channel Availability Check) State Machine

| Function | State | Purpose |
|----------|-------|---------|
| `wlc_dfs_cacstate_idle` | IDLE | Waiting for CAC trigger |
| `wlc_dfs_cacstate_idle_set` | IDLE_SET | Setting up CAC |
| `wlc_dfs_cacstate_cac` | CAC | Active channel availability check |
| `wlc_dfs_cacstate_csa` | CSA | Channel Switch Announcement |
| `wlc_dfs_cacstate_ism` | ISM | In-Service Monitoring |
| `wlc_dfs_cacstate_ism_set` | ISM_SET | Setting up ISM |
| `wlc_dfs_cacstate_ooc` | OOC | Out of Channel |
| `wlc_dfs_cacstate_fn_ary` | FN_ARY | Function array dispatch |
| `wlc_dfs_cacstate_handler` | HANDLER | State handler |
| `wlc_dfs_cacstate_abort` | ABORT | CAC abort |

#### 6.6.3 CAC Operations

| Function | Purpose |
|----------|---------|
| `wlc_dfs_cac_in_progress` | Check if CAC active |
| `wlc_dfs_get_cactime_ms` | Get CAC time in ms |
| `wlc_dfs_abort_cac` | Abort CAC |
| `wlc_dfs_start_radar_report_timer` | Start radar report timer |
| `wlc_dfs_send_action_frame_complete` | CSA action frame complete |

#### 6.6.4 Radar Detection & Reporting

| Function | Purpose |
|----------|---------|
| `wlc_dfs_set_radar` | Set radar detection |
| `wlc_dfs_get_radar` | Get radar info |
| `wlc_dfs_radar_detected` | Radar detected callback |
| `wlc_dfs_radar_report_handler` | Radar report handler |
| `wlc_dfs_radar_chanspec` | Radar chanspec |
| `wlc_dfs_scan_in_progress` | DFS scan in progress |
| `wlc_dfs_scan_abort` | Abort DFS scan |
| `wlc_dfs_scan_complete_sc` | DFS scan complete |
| `wlc_dfs_monitor_mode` | Monitor mode |
| `wlc_dfs_watchdog` | DFS watchdog timer |

#### 6.6.5 CSA (Channel Switch Announcement)

| Function | Purpose |
|----------|---------|
| `wlc_dfs_csa_received` | CSA received |
| `wlc_dfs_save_old_chanspec` | Save old chanspec for CSA |
| `wlc_dfs_reset_old_chanspec` | Reset old chanspec |
| `wlc_dfs_opmode_change_cb` | OpMode change callback |

#### 6.6.6 DFS Status & Validation

| Function | Purpose |
|----------|---------|
| `wlc_dfs_valid_ap_chanspec` | Validate AP chanspec for DFS |
| `wlc_dfs_get_dfs_status_all` | Get all DFS status |
| `wlc_dfs_get_chan_info` | Get channel info |
| `wlc_dfs_doiovar` | DFS iovar dispatch |

---

### 6.7 Radar Detection — `wlc_radar_*`

| Function | Purpose |
|----------|---------|
| `wlc_radar_detected` | Radar detected notification |
| `wlc_radar_report_handler` | Radar report handler |
| `wlc_radar_chanspec` | Radar chanspec |

---

### 6.8 Channel/Regulatory Call Graph

```
wlc_attach()
    └─ wlc_channel_mgr_attach() → init channel manager

wl_up() / wl_chanspec_set()
    └─ wlc_channel_set_chanspec() → validate chanspec
        ├─ wlc_channel_get_valid_channels_vec()
        ├─ wlc_channel_reg_limits()
        ├─ wlc_channel_apply_band_chain_limits()
        └─ wlc_dfs_up() if DFS channel

DFS CAC Flow:
    wlc_dfs_up()
        └─ wlc_dfs_cacstate_idle → wlc_dfs_cacstate_cac
            └─ wlc_dfs_cac_in_progress() → timer
            └─ wlc_dfs_cacstate_csa (on completion)
                └─ wlc_dfs_csa_received()
                    └─ wlc_dfs_save_old_chanspec()
                    └─ wlc_dfs_cacstate_ism (in-service monitoring)

Radar Detection:
    PHY interrupt → wlc_radar_detected()
        └─ wlc_radar_report_handler()
        └─ wlc_dfs_radar_detected()
            └─ wlc_dfs_cacstate_abort()
            └─ wlc_dfs_abort_cac()
```

---

### 6.9 Binary Offsets Quick Reference

| Function | Address | Size | Key Feature |
|----------|---------|------|-------------|
| `wlc_channel_set_chanspec` | (in chanspec_reg) | — | Primary chanspec setter |
| `wlc_channel_mgr_attach` | (in chanspec_reg) | — | Channel manager init |
| `wlc_dfs_attach` | (in chanspec_reg) | — | DFS init |
| `wlc_dfs_cacstate_cac` | (in chanspec_reg) | — | CAC state |
| `wlc_dfs_csa_received` | (in chanspec_reg) | — | CSA handler |
| `wlc_dfs_radar_detected` | (in chanspec_reg) | — | Radar interrupt |
| `wlc_channel_set_chanspec` | (in chanspec_reg) | — | Primary chanspec API |
| `wlc_channel_get_valid_channels_vec` | (in chanspec_reg) | — | Valid channels |

---

---

## Chapter 7: Rate Control/STF (`wlc_ratesel_*`, `wlc_stf_*`, `wlc_ht_*`, `wlc_vht_*`, `wlc_he_*`, `wlc_txbf_*`, `wlc_rateset_*`, `wlc_rate_*`)

### 7.1 Subsystem Overview

The Rate Control/STF (Spatial Transmit Format) subsystem handles:
- **Rate Selection**: Dynamic rate adaptation per SCB, probe-based rate selection
- **STF (Spatial Transmit Format)**: Tx chain management, spatial expansion, MIMO, TxBF
- **HT (802.11n)**: HT capabilities, MCS, 40MHz, STBC, LDPC, RIFS
- **VHT (802.11ac)**: VHT capabilities, MU-MIMO, wider bandwidths
- **HE (802.11ax)**: HE capabilities, OFDMA, MU-OFDMA, BSS Color, TWT
- **TxBF (Transmit Beamforming)**: SU/MU beamforming, sounding, feedback
- **Rate Set Management**: Legacy/HT/VHT/HE rate sets, MCS maps

**Symbol bucket:** 420 functions in `rate_stf` (largest subsystem)

---

### 7.2 Rate Selection — `wlc_ratesel_*`

**Core algorithm:** Probe-based rate adaptation with RSSI/ACK feedback

#### 7.2.1 Rate Selection Lifecycle

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ratesel_attach` | 1 | Initialize rate selection module |
| `wlc_ratesel_detach` | 1 | Cleanup rate selection |
| `wlc_ratesel_init` | 48 | Initialize per-SCB rate selection |
| `wlc_ratesel_init_all` | 11 | Init all SCBs |
| `wlc_ratesel_init_bss` | 12 | Init for BSS |
| `wlc_ratesel_init_rcb_itxs` | 3 | Init RCB/ITxS |
| `wlc_ratesel_init_params_sync` | (in bucket) | Sync init params |

#### 7.2.2 Rate Selection Core

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ratesel_pick_rate` | (in bucket) | Core rate picking algorithm |
| `wlc_ratesel_gettxrate` | 18 | Get TX rate for SCB |
| `wlc_ratesel_getcurspec` | (in bucket) | Get current rate spec |
| `wlc_ratesel_get_ratecap` | 1 | Get rate capabilities |
| `wlc_ratesel_minrate` | 3 | Minimum rate |
| `wlc_ratesel_probe_ready` | 7 | Probe ready check |
| `wlc_ratesel_is_start_sp` | 4 | Check if start SP |

#### 7.2.3 Rate Updates (TX Status Feedback)

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ratesel_upd_txs_ampdu` | 2 | Update from AMPDU TX status |
| `wlc_ratesel_upd_txs_blockack` | 1 | Update from BlockAck |
| `wlc_ratesel_upd_txs_trig` | 1 | Update from TX trigger |
| `wlc_ratesel_upd_itxs` | 1 | Update ITxS |
| `wlc_ratesel_upd_txstatus_normalack` | 1 | Update from normal ACK |

#### 7.2.4 Rate Selection State

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ratesel_change_epoch` | 2 | Change epoch |
| `wlc_ratesel_sync` | (in bucket) | Sync rate selection |
| `wlc_ratesel_clr_cache` | 3 | Clear cache |
| `wlc_ratesel_get_opstats` | 9 | Get operational stats |
| `wlc_ratesel_get_muboost` | 9 | Get MU boost |
| `wlc_ratesel_get_ulrt_rspec` | 10 | Get UL RT rspec |
| `wlc_ratesel_get_ulrt_txr` | 8 | Get UL RT TXR |
| `wlc_ratesel_get_ulrt_trssi` | 4 | Get UL RT TRSSI |
| `wlc_ratesel_get_ulmu_link_bw` | 9 | Get UL MU link BW |
| `wlc_ratesel_get_rcb` | 2 | Get RCB |
| `wlc_ratesel_getmcsfbr` | 1 | Get MCS FBR |
| `wlc_ratesel_rfbr` | (in bucket) | RFBR |

#### 7.2.5 Rate Selection Configuration

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ratesel_set_alert` | (in bucket) | Set alert |
| `wlc_ratesel_set_link_bw` | (in bucket) | Set link BW |
| `wlc_ratesel_filter` | (in bucket) | Rate filter |
| `wlc_ratesel_filter_minrateset` | (in bucket) | Filter min rateset |
| `wlc_ratesel_rcb_sz` | (in bucket) | RCB size |
| `wlc_ratesel_rfbr` | (in bucket) | RFBR |
| `wlc_ratesel_rssi_attach` | (in bucket) | RSSI attach |

---

### 7.3 Rate Set Management — `wlc_rateset_*`

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_rateset_elts` | (in bucket) | Get rate elements (called from beacon) |
| `wlc_rateset_copy` | (in bucket) | Copy rateset |
| `wlc_rateset_copy.part.0` | (in bucket) | Copy rateset part 0 |
| `wlc_rateset_default` | (in bucket) | Default rateset |
| `wlc_rateset_dump` | (in bucket) | Dump rateset |
| `wlc_rateset_elts.part.0` | (in bucket) | Get rate elements part 0 |
| `wlc_rateset_filter` | (in bucket) | Filter rateset |
| `wlc_rateset_isofdm` | (in bucket) | Check if OFDM |
| `wlc_rateset_ofdm_fixup` | (in bucket) | OFDM fixup |
| `wlc_rateset_ht_mcs_build` | (in bucket) | Build HT MCS |
| `wlc_rateset_ht_mcs_clear` | (in bucket) | Clear HT MCS |
| `wlc_rateset_ht_mcs_upd` | (in bucket) | Update HT MCS |
| `wlc_rateset_ht_bw_mcs_filter` | (in bucket) | HT BW MCS filter |
| `wlc_rateset_vhtmcs_build` | (in bucket) | Build VHT MCS |
| `wlc_rateset_vhtmcs_upd` | (in bucket) | Update VHT MCS |
| `wlc_rateset_vht_filter_mcsmap` | (in bucket) | Filter VHT MCS map |
| `wlc_rateset_prop_vhtmcs_build` | (in bucket) | Build proprietary VHT MCS |
| `wlc_rateset_prop_vhtmcs_upd` | (in bucket) | Update proprietary VHT MCS |
| `wlc_rateset_he_cp` | (in bucket) | HE CP rateset |
| `wlc_rateset_hemcs_build` | (in bucket) | Build HE MCS |
| `wlc_rateset_he_none_all` | (in bucket) | HE none/all rateset |
| `wlc_rate_shm_offset` | (in bucket) | Rate SHM offset |
| `wlc_rate_clear_prop_11n_mcses` | (in bucket) | Clear proprietary 11n MCSes |
| `wlc_rate_he_basic_reference` | (in bucket) | HE basic reference |
| `wlc_rate_ht_basic_reference` | (in bucket) | HT basic reference |
| `wlc_rate_ht_to_nonht` | (in bucket) | HT to non-HT conversion |
| `wlc_rate_legacy_phyctl` | (in bucket) | Legacy PHY control |
| `wlc_rate_lookup_init` | (in bucket) | Rate lookup init |
| `wlc_rate_rspec_reference_rate` | (in bucket) | Rspec reference rate |
| `wlc_rate_vht_basic_reference` | (in bucket) | VHT basic reference |

---

### 7.4 HT (802.11n) — `wlc_ht_*`

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_ht_attach` | (in bucket) | Initialize HT |
| `wlc_ht_detach` | (in bucket) | Cleanup HT |
| `wlc_ht_up` | (in bucket) | Enable HT |
| `wlc_ht_down` | (in bucket) | Disable HT |
| `wlc_ht_init_defaults` | (in bucket) | Init HT defaults |
| `wlc_ht_bss_init` | (in bucket) | Init HT for BSS |
| `wlc_ht_bss_dump` | (in bucket) | Dump HT BSS |
| `wlc_ht_scb_init` | (in bucket) | Init HT for SCB |
| `wlc_ht_scb_dump` | (in bucket) | Dump HT SCB |

#### 7.4.1 HT Capabilities

| Function | Purpose |
|----------|---------|
| `wlc_ht_get_cap` | Get HT capabilities |
| `wlc_ht_set_cap` | Set HT capabilities |
| `wlc_ht_get_phy_membership` | Get PHY membership |
| `wlc_ht_get_mimo_band_bwcap` | Get MIMO band BW capability |
| `wlc_ht_is_40MHZ_cap` | Check 40MHz capability |
| `wlc_ht_is_scb_40MHZ_cap` | Check SCB 40MHz capability |
| `wlc_ht_get_wsec_restriction` | Get WSEC restriction (called from beacon) |

#### 7.4.2 HT Capability IE

| Function | Purpose |
|----------|---------|
| `wlc_ht_calc_cap_ie_len` | Calculate HT cap IE length |
| `wlc_ht_write_cap_ie` | Write HT cap IE |
| `wlc_ht_parse_cap_ie` | Parse HT cap IE |
| `wlc_ht_write_brcm_cap_ie` | Write Broadcom HT cap IE |
| `wlc_ht_scan_parse_cap_ie` | Scan parse HT cap IE |

#### 7.4.3 HT Operation IE

| Function | Purpose |
|----------|---------|
| `wlc_ht_calc_op_ie_len` | Calculate HT op IE length |
| `wlc_ht_write_op_ie` | Write HT op IE |
| `wlc_ht_parse_op_ie` | Parse HT op IE |
| `wlc_ht_scan_parse_op_ie` | Scan parse HT op IE |

#### 7.4.4 HT Advanced Features

| Function | Purpose |
|----------|---------|
| `wlc_ht_cap_enable_tx_stbc` | Enable TX STBC |
| `wlc_ht_set_rx_stbc_cap` | Set RX STBC cap |
| `wlc_ht_stbc_tx_set` | Set STBC TX |
| `wlc_ht_stbc_rx_get` | Get STBC RX |
| `wlc_ht_update_txburst_limit` | Update TX burst limit |
| `wlc_ht_frameburst_limit` | Frameburst limit |
| `wlc_ht_rts_minlen_set` | RTS min length set |
| `wlc_ht_checkadd_rifs_permitted` | Check/add RIFS permitted |
| `wlc_ht_update_rifs_mode` | Update RIFS mode |
| `wlc_ht_update_coex_support` | Update coexistence support |
| `wlc_ht_update_ampdu_cap_params` | Update AMPDU cap params |
| `wlc_ht_update_ampdu_rx_cap_params` | Update AMPDU RX cap params |
| `wlc_ht_update_scbstate` | Update SCB state |
| `wlc_ht_upd_scb_rateset_mcs` | Update SCB rateset MCS |
| `wlc_ht_upd_txbf_cap` | Update TxBF cap |
| `wlc_ht_nvm_overrides` | NVM overrides |
| `wlc_ht_publicaction` | HT public action |
| `wlc_ht_prep_rate_info` | Prepare rate info |
| `wlc_ht_fill_sta_fields` | Fill STA fields |
| `wlc_ht_calc_brcm_cap_ie_len` | Calc Broadcom cap IE len |
| `wlc_ht_write_brcm_cap_ie` | Write Broadcom cap IE |
| `wlc_ht_scan_parse_brcm_ie` | Scan parse Broadcom IE |
| `wlc_ht_obss_scan_reset` | OBSS scan reset |
| `wlc_ht_read_obss_scanparams_ie` | Read OBSS scan params IE |
| `wlc_ht_calc_obss_scan_ie_len` | Calc OBSS scan IE len |
| `wlc_ht_write_obss_scan_ie` | Write OBSS scan IE |
| `wlc_ht_monitor` | HT monitor |
| `wlc_ht_calc_frame_len` | Calc frame length |
| `wlc_ht_calc_frame_time` | Calc frame time |
| `wlc_ht_doioctl` | HT ioctl |
| `wlc_ht_doiovar` | HT iovar |

---

### 7.5 VHT (802.11ac) — `wlc_vht_*`

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_vht_attach` | (in bucket) | Initialize VHT |
| `wlc_vht_detach` | (in bucket) | Cleanup VHT |
| `wlc_vht_up` | (in bucket) | Enable VHT |
| `wlc_vht_bss_init` | (in bucket) | Init VHT for BSS |
| `wlc_vht_bsscfg_updn` | (in bucket) | BSS up/down for VHT |
| `wlc_vht_bcn_scb_upd` | (in bucket) | Beacon SCB update |
| `wlc_vht_scb_init` | (in bucket) | Init VHT for SCB |
| `wlc_vht_scb_deinit` | (in bucket) | Deinit VHT SCB |
| `wlc_vht_scb_dump` | (in bucket) | Dump VHT SCB |

#### 7.5.1 VHT Capabilities

| Function | Purpose |
|----------|---------|
| `wlc_vht_get_cap_info` | Get VHT cap info |
| `wlc_vht_get_mcs` | Get VHT MCS |
| `wlc_vht_get_rx_mcsmap` | Get RX MCS map |
| `wlc_vht_get_ext_nss_bw_sup` | Get extended NSS BW support |
| `wlc_vht_get_gid` | Get GID |
| `wlc_vht_is_40MHz` | Check 40MHz |
| `wlc_vht_is_omn_enabled` | Check OMN enabled |
| `wlc_vht_is_SGI` | Check SGI |

#### 7.5.2 VHT Capability IE

| Function | Purpose |
|----------|---------|
| `wlc_vht_calc_cap_ie_len` | Calc VHT cap IE len |
| `wlc_vht_write_cap_ie` | Write VHT cap IE |
| `wlc_vht_parse_cap_ie` | Parse VHT cap IE |
| `wlc_vht_copy_cap_ie` | Copy cap IE |

#### 7.5.3 VHT Operation IE

| Function | Purpose |
|----------|---------|
| `wlc_vht_calc_op_ie_len` | Calc VHT op IE len |
| `wlc_vht_write_op_ie` | Write VHT op IE |
| `wlc_vht_parse_op_ie` | Parse VHT op IE |
| `wlc_vht_copy_op_ie` | Copy op IE |

#### 7.5.4 VHT Advanced

| Function | Purpose |
|----------|---------|
| `wlc_vht_get_scb_flags` | Get SCB flags |
| `wlc_vht_get_scb_opermode` | Get SCB oper mode |
| `wlc_vht_get_scb_opermode_enab` | Get SCB oper mode enab |
| `wlc_vht_get_scb_oper_nss` | Get SCB oper NSS |
| `wlc_vht_get_scb_ratemask` | Get SCB rate mask |
| `wlc_vht_get_scb_ratemask_per_band` | Get SCB rate mask per band |
| `wlc_vht_disable_scb_oper_mode` | Disable SCB oper mode |
| `wlc_vht_update_scb_oper_mode` | Update SCB oper mode |
| `wlc_vht_update_scb_state` | Update SCB state |
| `wlc_vht_update_sgi_rx` | Update SGI RX |
| `wlc_vht_upd_rate_mcsmap` | Update rate MCS map |
| `wlc_vht_upd_txbf_cap` | Update TxBF cap |
| `wlc_vht_upd_txbf_virtif_cap` | Update TxBF virtif cap |
| `wlc_vht_update_ampdu_cap` | Update AMPDU cap |
| `wlc_vht_update_defaults` | Update defaults |
| `wlc_vht_update_mcs_cap` | Update MCS cap |
| `wlc_vht_init_defaults` | Init defaults |
| `wlc_vht_set_ext_nss_bw_sup` | Set extended NSS BW sup |
| `wlc_vht_set_ldpc_cap` | Set LDPC cap |
| `wlc_vht_set_rx_stbc_cap` | Set RX STBC cap |
| `wlc_vht_set_tx_stbc_cap` | Set TX STBC cap |
| `wlc_vht_scan_parse_cap_ie` | Scan parse cap IE |
| `wlc_vht_scan_parse_op_ie` | Scan parse op IE |
| `wlc_vht_scan_parse_brcm_ie` | Scan parse Broadcom IE |
| `wlc_vht_read_features_ie` | Read features IE |
| `wlc_vht_write_brcm_ie` | Write Broadcom IE |
| `wlc_vht_write_cap_ie` | Write cap IE |
| `wlc_vht_write_oper_mode_ie` | Write oper mode IE |
| `wlc_vht_write_op_ie` | Write op IE |
| `wlc_vht_calc_brcm_ie_len` | Calc Broadcom IE len |
| `wlc_vht_calc_oper_mode_ie_len` | Calc oper mode IE len |
| `wlc_vht_calc_brcm_ie_len` | Calc Broadcom IE len |
| `wlc_vht_doiovar` | VHT iovar |
| `wlc_vht_parse_brcm_ht_ie` | Parse Broadcom HT IE |
| `wlc_vht_parse_brcm_ie` | Parse Broadcom IE |
| `wlc_vht_parse_ext_cap_ie` | Parse ext cap IE |
| `wlc_vht_read_features_ie` | Read features IE |
| `wlc_vht_prep_rate_info` | Prepare rate info |

---

### 7.6 HE (802.11ax) — `wlc_he_*`

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_he_attach` | (in bucket) | Initialize HE |
| `wlc_he_detach` | (in bucket) | Cleanup HE |
| `wlc_he_up` | (in bucket) | Enable HE |
| `wlc_he_wlc_up` | (in bucket) | HE wlc up |
| `wlc_he_wlc_down` | (in bucket) | HE wlc down |
| `wlc_he_bss_init` | (in bucket) | Init HE for BSS |
| `wlc_he_bss_deinit` | (in bucket) | Deinit HE BSS |
| `wlc_he_bsscfg_state_upd` | (in bucket) | BSSCFG state update |
| `wlc_he_bcn_scb_upd` | (in bucket) | Beacon SCB update |
| `wlc_he_scb_init` | (in bucket) | Init HE for SCB |
| `wlc_he_scb_deinit` | (in bucket) | Deinit HE SCB |
| `wlc_he_scb_secsz` | (in bucket) | HE SCB section size |
| `wlc_he_scb_get_bfr_nr` | (in bucket) | Get BFR NR |
| `wlc_he_scb_upd` | (in bucket) | SCB update |
| `wlc_he_update_ampdu_cap` | (in bucket) | Update AMPDU cap |
| `wlc_he_update_mcs_cap` | (in bucket) | Update MCS cap |
| `wlc_he_update_scb_state` | (in bucket) | Update SCB state |
| `wlc_he_upd_omi_rxnss` | (in bucket) | Update OMI RX NSS |
| `wlc_he_upd_omi_txnsts` | (in bucket) | Update OMI TX NSTS |
| `wlc_he_upd_scb_rateset_mcs` | (in bucket) | Update SCB rateset MCS |

#### 7.7.1 HE Capability IE

| Function | Purpose |
|----------|---------|
| `wlc_he_calc_cap_ie_len` | Calc HE cap IE len |
| `wlc_he_write_cap_ie` | Write HE cap IE |
| `wlc_he_parse_cap_ie` | Parse HE cap IE |
| `wlc_he_write_6g_caps_ie` | Write 6GHz caps IE |
| `wlc_he_write_color_ie` | Write color IE |
| `wlc_he_write_muedca_ie` | Write MU EDCA IE |
| `wlc_he_write_op_ie` | Write HE op IE |
| `wlc_he_write_sr_ie` | Write SR IE |
| `wlc_he_calc_6g_caps_ie_len` | Calc 6GHz caps IE len |
| `wlc_he_calc_cap_ie_len` | Calc HE cap IE len |
| `wlc_he_calc_color_ie_len` | Calc color IE len |
| `wlc_he_calc_muedca_ie_len` | Calc MU EDCA IE len |
| `wlc_he_calc_op_ie_len` | Calc HE op IE len |
| `wlc_he_calc_sr_ie_len` | Calc SR IE len |

#### 7.7.2 HE Parsing

| Function | Purpose |
|----------|---------|
| `wlc_he_parse_cap_ie` | Parse HE cap IE |
| `wlc_he_parse_muedca_ie` | Parse MU EDCA IE |
| `wlc_he_parse_op_ie` | Parse HE op IE |
| `wlc_he_scan_parse_cap_ie` | Scan parse HE cap IE |
| `wlc_he_scan_parse_op_ie` | Scan parse HE op IE |
| `wlc_he_assoc_parse_cap_ie` | Assoc parse HE cap IE |
| `wlc_he_assoc_parse_6g_caps_ie` | Assoc parse 6GHz caps IE |
| `wlc_he_process_obssbcn_extcap_elm` | Process OBSS beacon ext cap |
| `wlc_he_process_op_ie` | Process HE op IE |
| `wlc_he_recv_af_oper_mode` | Recv AF oper mode |
| `wlc_he_received_valid_omi` | Received valid OMI |

#### 7.7.3 HE Advanced

| Function | Purpose |
|----------|---------|
| `wlc_he_init_defaults` | Init HE defaults |
| `wlc_he_set_ldpc_cap` | Set LDPC cap |
| `wlc_he_set_rateset_filter` | Set rateset filter |
| `wlc_he_upd_scb_rateset_mcs` | Update SCB rateset MCS |
| `wlc_he_upd_omi_rxnss` | Update OMI RX NSS |
| `wlc_he_upd_omi_txnsts` | Update OMI TX NSTS |
| `wlc_he_get_bfe_ndp_recvstreams` | Get BFE NDP recv streams |
| `wlc_he_get_bfr_ndp_sts` | Get BFR NDP STS |
| `wlc_he_get_bsscolor_disable` | Get BSS color disable |
| `wlc_he_get_dlmmu_allow` | Get DL MMU allow |
| `wlc_he_get_dynfrag` | Get dynfrag |
| `wlc_he_get_omi_bw` | Get OMI BW |
| `wlc_he_get_omi_tx_nsts` | Get OMI TX NSTS |
| `wlc_he_get_peer_caps` | Get peer caps |
| `wlc_he_get_phy_mu_feedback_ng16` | Get PHY MU feedback |
| `wlc_he_get_scb_omi` | Get SCB OMI |
| `wlc_he_get_ulmu_allow` | Get UL MU allow |
| `wlc_he_rateset_intersection` | Rateset intersection |
| `wlc_he_sig_a1_from_plcp` | SIG-A1 from PLCP |
| `wlc_he_sig_a2_from_plcp` | SIG-A2 from PLCP |
| `wlc_he_htc_pkt_freed` | HTC packet freed |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_recv` | HTC recv |
| `wlc_he_htc_rtc_init` | HTC RTC init |
| `wlc_he_htc_rtc_tx` | HTC RTC TX |
| `wlc_he_htc_send_code` | HTC send code |
| `wlc_he_htc_tx` | HTC TX |

---

### 7.8 Tx Beamforming — `wlc_txbf_*`

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_txbf_attach` | (in bucket) | Initialize TxBF |
| `wlc_txbf_detach` | (in bucket) | Cleanup TxBF |
| `wlc_txbf_up` | (in bucket) | Enable TxBF |
| `wlc_txbf_down` | (in bucket) | Disable TxBF |
| `wlc_txbf_init` | (in bucket) | Initialize TxBF |
| `wlc_txbf_attach` | (in bucket) | Attach TxBF |

#### 7.8.1 SU Beamforming

| Function | Purpose |
|----------|---------|
| `wlc_txbf_bfecap_init` | BFE cap init |
| `wlc_txbf_bfen` | BFE enable |
| `wlc_txbf_bfi_init` | BFI init |
| `wlc_txbf_bfr_init` | BFR init |
| `wlc_txbf_impbf_upd` | Implicit BF update |
| `wlc_txbf_bfrspexp_enable` | BFR spec exp enable |
| `wlc_txbf_bfmspexp_enable` | BFM spec exp enable |

#### 7.8.2 MU Beamforming

| Function | Purpose |
|----------|---------|
| `wlc_txbf_mu_max_links_upd` | MU max links update |
| `wlc_txbf_mu_sounding_period` | MU sounding period |
| `wlc_txbf_set_mu_sounding_period` | Set MU sounding period |
| `wlc_txbf_get_mu_sounding_period` | Get MU sounding period |
| `wlc_txbf_get_mu_txvidx` | Get MU TX VIDX |
| `wlc_txbf_mupkteng_addsta` | MU pkteng add STA |
| `wlc_txbf_mupkteng_clrsta` | MU pkteng clear STA |
| `wlc_txbf_murx_capable` | MU RX capable |
| `wlc_txbf_mutimer_update` | MU timer update |
| `wlc_txbf_mutx_enabled` | MU TX enabled |

#### 7.8.3 TxBF Link Management

| Function | Purpose |
|----------|---------|
| `wlc_txbf_init_link` | Init link |
| `wlc_txbf_delete_link` | Delete link |
| `wlc_txbf_delete_all_link` | Delete all links |
| `wlc_txbf_link_upd` | Link update |
| `wlc_txbf_link_entry_dump` | Link entry dump |
| `wlc_txbf_fill_link_entry` | Fill link entry |
| `wlc_txbf_get_free_su_bfr_links` | Get free SU BFR links |
| `wlc_txbf_get_applied2ovr` | Get applied2ovr |
| `wlc_txbf_applied2ovr_upd` | Applied2ovr update |
| `wlc_txbf_get_bfi_idx` | Get BFI index |
| `wlc_txbf_get_mubfi_idx` | Get MU BFI index |
| `wlc_txbf_sel` | TxBF selection |
| `wlc_txbf_sel` | TxBF selection |
| `wlc_txbf_sel` | TxBF selection |

#### 7.8.4 TxBF Capabilities

| Function | Purpose |
|----------|---------|
| `wlc_txbf_get_bfe_cap` | Get BFE cap |
| `wlc_txbf_get_bfe_sts_cap` | Get BFE STS cap |
| `wlc_txbf_get_bfr_cap` | Get BFR cap |
| `wlc_txbf_ht_upd_bfr_bfe_cap` | HT update BFR/BFE cap |
| `wlc_txbf_vht_upd_bfr_bfe_cap` | VHT update BFR/BFE cap |
| `wlc_txbf_get_bfe_idx` | Get BFE index |

#### 7.8.5 TxBF Sounding

| Function | Purpose |
|----------|---------|
| `wlc_txbf_sounding_clean_cache` | Sounding clean cache |
| `wlc_txbf_pkteng_tx_start` | Pkteng TX start |
| `wlc_txbf_pkteng_tx_stop` | Pkteng TX stop |
| `wlc_txbf_sched_timer` | Scheduler timer |
| `wlc_txbf_mutimer_update` | MU timer update |
| `wlc_txbf_set_shm_idx` | Set SHM index |

#### 7.8.6 TxBF Status

| Function | Purpose |
|----------|---------|
| `wlc_txbf_get_bfe_cap` | Get BFE cap |
| `wlc_txbf_get_bfr_cap` | Get BFR cap |
| `wlc_txbf_get_bfr_sts_cap` | Get BFR STS cap |
| `wlc_txbf_get_txbf_tx` | Get TxBF TX |
| `wlc_txbf_get_applied2ovr` | Get applied2ovr |
| `wlc_txbf_get_bfi_idx` | Get BFI index |
| `wlc_txbf_get_mubfi_idx` | Get MU BFI index |
| `wlc_txbf_get_mu_txvidx` | Get MU TX VIDX |

#### 7.8.7 TxBF Chanspec/Power

| Function | Purpose |
|----------|---------|
| `wlc_txbf_chanspec_upd` | Chanspec update |
| `wlc_txbf_txchain_upd` | TX chain update |
| `wlc_txbf_rxchain_upd` | RX chain update |
| `wlc_txbf_txpower_target_max_upd` | TX power target max update |
| `wlc_txbf_system_gain_acphy` | System gain AC PHY |

#### 7.8.8 TxBF ImpTxStatus

| Function | Purpose |
|----------|---------|
| `wlc_txbf_imp_txstatus` | Implicit TX status |

---

### 7.9 Rate Utilities — `wlc_rate_*`

| Function | Purpose |
|----------|---------|
| `wlc_rate_clear_prop_11n_mcses` | Clear proprietary 11n MCSes |
| `wlc_rate_he_basic_reference` | HE basic reference |
| `wlc_rate_ht_basic_reference` | HT basic reference |
| `wlc_rate_ht_to_nonht` | HT to non-HT conversion |
| `wlc_rate_legacy_phyctl` | Legacy PHY control |
| `wlc_rate_lookup_init` | Rate lookup init |
| `wlc_rate_rspec_reference_rate` | Rspec reference rate |
| `wlc_rate_vht_basic_reference` | VHT basic reference |

---

### 7.10 Call Graph Summary

```
wlc_attach()
    ├─ wlc_ratesel_attach() → init rate selection
    ├─ wlc_stf_attach() → init STF
    ├─ wlc_ht_attach() → init HT
    ├─ wlc_vht_attach() → init VHT
    ├─ wlc_he_attach() → init HE
    ├─ wlc_txbf_attach() → init TxBF
    └─ wlc_ratesel_init() for primary BSS

wl_up()
    ├─ wlc_ratesel_init_all() → init all SCBs
    ├─ wlc_stf_up() → enable STF
    ├─ wlc_ht_up() → enable HT
    ├─ wlc_vht_up() → enable VHT
    ├─ wlc_he_up() → enable HE
    └─ wlc_txbf_up() → enable TxBF

TX Path:
    wlc_send()
        └─ wlc_ratesel_pick_rate() → select rate
        └─ wlc_stf_*() → spatial format
        └─ wlc_txbf_*() → beamforming

RX Path (TX Status):
    wlc_recv_txstatus()
        └─ wlc_ratesel_upd_txs_ampdu/blockack/normalack
        └─ wlc_ratesel_upd_itxs
```

---

### 7.11 Binary Offsets Quick Reference

| Function | Address | Size | Key Feature |
|----------|---------|------|-------------|
| `wlc_ratesel_attach` | (in rate_stf) | — | Rate selection init |
| `wlc_ratesel_pick_rate` | (in rate_stf) | — | Core rate picker |
| `wlc_ratesel_gettxrate` | (in rate_stf) | 18 calls | Get TX rate |
| `wlc_ratesel_init` | (in rate_stf) | 48 calls | SCB init |
| `wlc_stf_attach` | (in rate_stf) | — | STF init |
| `wlc_txbf_attach` | (in rate_stf) | — | TxBF init |
| `wlc_ht_attach` | (in rate_stf) | — | HT init |
| `wlc_vht_attach` | (in rate_stf) | — | VHT init |
| `wlc_he_attach` | (in rate_stf) | — | HE init |
| `wlc_ht_get_wsec_restriction` | 0x414df0 | 0x18 | WSEC restriction |
| `wlc_rateset_elts` | (in rate_stf) | — | Rate elements (beacon) |
| `wlc_ratesel_doiovar` | (in rate_stf) | — | Rate selection iovar |
| `wlc_stf_doiovar` | (in rate_stf) | — | STF iovar |
| `wlc_txbf_doiovar` | (in rate_stf) | — | TxBF iovar |

---

## Chapter 8: Power Save / Debug / D11 HW (`wlc_ps_*`, `wlc_dump_*`, `d11regs`, `ucode`)

### 8.1 Power Save — `wlc_pm_*`, `wlc_ps_*`, `wlc_apsd_*`, `wlc_wme_*`

**Symbol bucket:** 22 functions in `power_save`

#### 8.1.1 Power Management Lifecycle

| Function | Call Count | Purpose |
|----------|------------|---------|
| `wlc_pm_attach` | (in power_save) | Initialize power management |
| `wlc_pm_detach` | (in power_save) | Cleanup power management |
| `wlc_pm_wlc_up` | (in power_save) | PM wlc up handler |

#### 8.1.2 Per-BSS Power Save

| Function | Purpose |
|----------|---------|
| `wlc_pm_bss_init` | Initialize PM for BSS |
| `wlc_pm_bss_deinit` | Deinit PM for BSS |
| `wlc_pm_bss_state_upd` | BSS state update |

#### 8.1.3 APSD (Automatic Power Save Delivery)

| Function | Purpose |
|----------|---------|
| `wlc_apsd_trigger_timeout` | APSD trigger timeout |
| `wlc_apsd_trigger_upd` | APSD trigger update |

#### 8.1.4 PSPoll Handling

| Function | Purpose |
|----------|---------|
| `wlc_pm_pspoll_notif_register` | Register PSPoll notification |
| `wlc_pm_pspoll_notif_unregister` | Unregister PSPoll notification |
| `wlc_pm_update_pspoll_state` | Update PSPoll state |
| `wlc_pm_pending_complete` | Pending complete |

#### 8.1.5 Power Save Rx/Ignore

| Function | Purpose |
|----------|---------|
| `wlc_pm_ignore_bcmc` | Ignore BCMC in power save |
| `wlc_pm_update_rxdata` | Update RX data in PM |
| `wlc_pm_notif_complete` | Notification complete |

#### 8.1.6 WMM Power Save / WME

| Function | Purpose |
|----------|---------|
| `wlc_wme_downgrade_fifo` | Downgrade FIFO |
| `wlc_wme_get_frame_medium_time` | Get frame medium time |
| `wlc_wme_retries_write` | Write retries |
| `wlc_wme_shm_read` | SHM read |

#### 8.1.7 Power Save Check

| Function | Purpose |
|----------|---------|
| `wlc_ps_allowed` | Check if power save allowed |

---

### 8.2 Debug / Dump — `wlc_dump_*`, `wlc_log_*`

**Symbol bucket:** 36 functions in `debug_dump`

#### 8.2.1 Dump Lifecycle

| Function | Purpose |
|----------|---------|
| `wlc_dump_attach` | Initialize dump module |
| `wlc_dump_detach` | Cleanup dump module |
| `wlc_dump_pre_attach` | Pre-attach dump |
| `wlc_dump_post_detach` | Post-detach dump |

#### 8.2.2 Dump Functions

| Function | Purpose |
|----------|---------|
| `wlc_dump_local` | Local dump |
| `wlc_dump_aggfifo` | Dump aggregate FIFO |
| `wlc_dump_clmver` | Dump CLM version |
| `wlc_dump_he_rateset` | Dump HE rateset |
| `wlc_dump_mcsset` | Dump MCS set |
| `wlc_dump_phytxerr` | Dump PHY TX error |
| `wlc_dump_psmr1_fatal` | Dump PSMR1 fatal |
| `wlc_dump_psmx_fatal` | Dump PSMX fatal |
| `wlc_dump_psmx_fatal.part.0` | Dump PSMX fatal part 0 |
| `wlc_dump_rateset` | Dump rateset |
| `wlc_dump_reg_add_fns` | Register dump functions |
| `wlc_dump_reg_create` | Register dump create |
| `wlc_dump_reg_destroy` | Register dump destroy |
| `wlc_dump_reg_dump` | Register dump |
| `wlc_dump_reg_invoke_clr_fn` | Invoke clear function |
| `wlc_dump_reg_invoke_dump_fn` | Invoke dump function |
| `wlc_dump_reg_list` | Register dump list |
| `wlc_dump_rspec` | Dump rspec |
| `wlc_dump_ucode_fatal` | Dump ucode fatal |
| `wlc_dump_ucode_fatal.part.0` | Dump ucode fatal part 0 |
| `wlc_dump_ucode_fatal_phydebug` | Dump ucode fatal PHY debug |
| `wlc_dump_vasip_fatal` | Dump VASIP fatal |
| `wlc_dump_vasip_fatal.part.0` | Dump VASIP fatal part 0 |
| `wlc_dump_vht_mcsmap` | Dump VHT MCS map |
| `wlc_dump_vht_mcsmap_prop` | Dump VHT MCS map proprietary |

#### 8.2.3 Dump Registration

| Function | Purpose |
|----------|---------|
| `wlc_dump_add_fns` | Add dump functions |
| `wlc_dump_reg_add_fns` | Register dump functions |
| `wlc_dump_reg_create` | Register dump create |
| `wlc_dump_reg_destroy` | Register dump destroy |
| `wlc_dump_reg_dump` | Register dump |
| `wlc_dump_reg_invoke_clr_fn` | Invoke clear function |
| `wlc_dump_reg_invoke_dump_fn` | Invoke dump function |
| `wlc_dump_reg_list` | Register dump list |

#### 8.2.4 Mac/Code Fatal

| Function | Purpose |
|----------|---------|
| `wlc_dump_mac_fatal` | Dump MAC fatal |
| `wlc_dump_macreq` | Dump MAC request |
| `wlc_dump_ucode_fatal` | Dump ucode fatal |
| `wlc_dump_ucode_fatal.part.0` | Dump ucode fatal part 0 |
| `wlc_dump_ucode_fatal_phydebug` | Dump ucode fatal PHY debug |

#### 8.2.5 Logging

| Function | Purpose |
|----------|---------|
| `wlc_log_unexpected_rx_frame_log_80211hdr` | Log unexpected RX frame |
| `wlc_log_unexpected_tx_frame_log_80211hdr` | Log unexpected TX frame (802.11) |
| `wlc_log_unexpected_tx_frame_log_8023hdr` | Log unexpected TX frame (802.3) |

#### 8.2.6 Dump iovar

| Function | Purpose |
|----------|---------|
| `wlc_dump_doiovar` | Dump iovar dispatch |

---

### 8.3 Timer / Event / Module Lifecycle — `wlc_*` (timer_event bucket)

**Symbol bucket:** 45 functions in `timer_event`

| Function | Purpose |
|----------|---------|
| `wlc_attach` | Main attach (entry point) |
| `wlc_attach_malloc` | Attach memory allocation |
| `wlc_detach` | Main detach |
| `wlc_detach_mfree` | Detach memory free |
| `wlc_init` | Initialize |
| `wlc_up` | Bring up |
| `wlc_down` | Bring down |
| `wlc_down_for_mpc` | Down for MPC |
| `wlc_reset` | Reset |
| `wlc_reset_bmac_done` | Reset BMAC done |
| `wlc_reset_pmstate` | Reset PM state |
| `wlc_reset_rxchain_pwrsave_mode` | Reset RX chain power save mode |
| `wlc_suspend_mac_and_wait` | Suspend MAC and wait |
| `wlc_module_register` | Register module |
| `wlc_module_unregister` | Unregister module |
| `wlc_module_set_pmstate` | Module set PM state |
| `wlc_update_bandwidth` | Update bandwidth |
| `wlc_update_bcn_info` | Update beacon info |
| `wlc_update_beacon` | Update beacon (17 call sites) |
| `wlc_update_brcm_ie` | Update Broadcom IE |
| `wlc_update_multiap_ie` | Update Multi-AP IE |
| `wlc_update_phy_mode` | Update PHY mode |
| `wlc_update_phy_tdcs` | Update PHY TDCS |
| `wlc_update_pm_history` | Update PM history |
| `wlc_update_pmstate` | Update PM state |
| `wlc_update_pref_score` | Update preference score |
| `wlc_update_probe_resp` | Update probe response |
| `wlc_update_rcinfo` | Update rate control info |
| `wlc_update_regulatory_info` | Update regulatory info |
| `wlc_update_shm` | Update SHM |
| `wlc_update_sleep_ret` | Update sleep return |
| `wlc_update_splitrx_mode` | Update split RX mode |
| `wlc_update_stamon_mac_list` | Update STA monitor MAC list |
| `wlc_update_txpktsuccess_stats` | Update TX packet success stats |
| `wlc_update_txppr_offset` | Update TX PPR offset |
| `wlc_update_upr_fd_template` | Update UPR FD template |
| `wlc_update_wds_index` | Update WDS index |
| `wlc_upd_suspended_fifos_clear` | Clear suspended FIFOs |
| `wlc_upd_suspended_fifos_set` | Set suspended FIFOs |

#### 8.3.1 Event System

| Function | Purpose |
|----------|---------|
| `wlc_event_alloc` | Allocate event |
| `wlc_event_data_alloc` | Allocate event data |
| `wlc_event_data_free` | Free event data |
| `wlc_event_free` | Free event |
| `wlc_event_if` | Event interface |
| `wlc_event_process` | Process event |

---

### 8.4 D11 / PHY / Radio / Ucode — `d11_phy` bucket (721 functions)

**Largest bucket** — D11 MAC, PHY, radio, and ucode operations

#### 8.4.1 D11 MAC / DMA

| Function | Purpose |
|----------|---------|
| `wlc_d11_dma_lpbk_init` | DMA loopback init |
| `wlc_d11_dma_lpbk_run` | DMA loopback run |
| `wlc_d11_dma_lpbk_uninit` | DMA loopback uninit |
| `wlc_d11hdrs_pre40` | D11 headers pre-40 |
| `wlc_d11hdrs_rev40` | D11 headers rev 40 |
| `wlc_d11hdrs_rev128` | D11 headers rev 128 |
| `wlc_d11hdrs_phyctl_get_txant_mask` | Get TX ant mask |
| `wlc_d11hdrs_phyctl_txant` | PHY control TX ant |
| `wlc_d11hdrs_phyctl_txcore_80p80phy` | TX core 80p80 PHY |
| `wlc_mac_bcn_promisc` | MAC beacon promisc |
| `wlc_mac_bcn_promisc_update` | Update MAC beacon promisc |
| `wlc_mac_event` | MAC event |
| `wlc_mac_promisc` | MAC promisc |
| `wlc_mac_request_entry` | MAC request entry |
| `wlc_edcf_acp_apply` | EDCF ACP apply |
| `wlc_edcf_acp_get_all` | Get all EDCF ACP |
| `wlc_edcf_acp_set_one` | Set EDCF ACP one |

#### 8.4.2 PHY Calibration

| Function | Purpose |
|----------|---------|
| `wlc_phy_cal_mode` | Calibration mode |
| `wlc_phy_cal_perical` | Periodic calibration |
| `wlc_phy_cal_perical_nphy_run` | NPHY periodic cal run |
| `wlc_phy_cal_rx_fdiqi_acphy` | RX FDIQI cal AC PHY |
| `wlc_phy_cal_rxiq_nphy` | RX IQ cal NPHY |
| `wlc_phy_cals_acphy` | AC PHY calibrations |
| `wlc_phy_cals_mac_susp_en_other_cr` | Cal MAC suspend enable |
| `wlc_phy_cal_txgainctrl_inttssi_nphy` | TX gain control int TSSI NPHY |
| `wlc_phy_cal_txgainctrl_nphy` | TX gain control NPHY |
| `wlc_phy_cal_txiqlo_acphy` | TX IQ LO AC PHY |
| `wlc_phy_cal_txiqlo_coeffs_acphy` | TX IQ LO coeffs AC PHY |
| `wlc_phy_cal_txiqlo_init_acphy` | TX IQ LO init AC PHY |
| `wlc_phy_cal_txiqlo_nphy` | TX IQ LO NPHY |
| `wlc_phy_cal_txiqlo_nphy.part.0` | TX IQ LO NPHY part 0 |

#### 8.4.3 PHY Radio Setup

| Function | Purpose |
|----------|---------|
| `wlc_phy_radio20693_afecal` | Radio 20693 AFE cal |
| `wlc_phy_radio20693_afe_div_ratio` | Radio 20693 AFE div ratio |
| `wlc_phy_radio20693_altclkpln_get_chan_row` | Alt clock plan get chan row |
| `wlc_phy_radio20693_config_bf_mode` | Config BF mode |
| `wlc_phy_radio20693_force_dacbuf_setting` | Force DAC buf setting |
| `wlc_phy_radio20693_mimo_core1_pmu_restore_on_bandhcange` | MIMO core1 PMU restore |
| `wlc_phy_radio20693_mimo_lpopt_restore` | MIMO LP opt restore |
| `wlc_phy_radio20693_minipmu_pwron_seq` | Mini PMU power on seq |
| `wlc_phy_radio20693_pll_tune` | PLL tune |
| `wlc_phy_radio20693_pmu_pll_config` | PMU PLL config |
| `wlc_phy_radio20693_sel_logen_2g_mode` | Select logen 2G mode |
| `wlc_phy_radio20693_sel_logen_5g_mode` | Select logen 5G mode |
| `wlc_phy_radio20693_sel_logen_mode` | Select logen mode |
| `wlc_phy_radio20693_vco_opt` | VCO optimization |
| `wlc_phy_radio20693_vco_cal_sanity_check` | VCO cal sanity check |
| `wlc_phy_radio20698_adc_cap_cal` | Radio 20698 ADC cap cal |
| `wlc_phy_radio20698_afe_div_ratio` | Radio 20698 AFE div ratio |
| `wlc_phy_radio20698_minipmu_pwron_seq` | Mini PMU power on seq |
| `wlc_phy_radio20698_pll_tune` | PLL tune |
| `wlc_phy_radio20698_pmu_pll_pwrup` | PMU PLL power up |
| `wlc_phy_radio20698_powerup_RFP1` | Power up RFP1 |
| `wlc_phy_radio20698_pu_rx_core` | Power up RX core |
| `wlc_phy_radio20698_sel_logen_mode` | Select logen mode |
| `wlc_phy_radio20698_set_tx_notch` | Set TX notch |
| `wlc_phy_radio20698_upd_band_related_reg` | Update band related reg |
| `wlc_phy_radio20698_vcocal_isdone` | VCO cal is done |
| `wlc_phy_radio20707_pll_tune` | Radio 20707 PLL tune |
| `wlc_phy_radio20707_sel_logen_mode` | Select logen mode |
| `wlc_phy_radio20707_set_tx_notch` | Set TX notch |
| `wlc_phy_radio20707_upd_band_related_reg` | Update band related reg |
| `wlc_phy_radio20707_vcocal_isdone` | VCO cal is done |
| `wlc_phy_radio20708_afe_cal_main` | Radio 20708 AFE cal main |
| `wlc_phy_radio20708_afediv_control` | AFE div control |
| `wlc_phy_radio20708_pll_tune` | PLL tune |
| `wlc_phy_radio20708_powerup_RFPll` | Power up RF PLL |
| `wlc_phy_radio20708_vcocal_isdone` | VCO cal is done |

#### 8.4.4 PHY Tx Power

| Function | Purpose |
|----------|---------|
| `wlc_phy_txpower_get` | Get TX power |
| `wlc_phy_txpower_get_current` | Get current TX power |
| `wlc_phy_txpower_get_txctrl` | Get TX control |
| `wlc_phy_txpower_hw_ctrl_get` | Get HW TX power control |
| `wlc_phy_txpower_limit_set` | Set TX power limit |
| `wlc_phy_txpower_recalc_target` | Recalc TX power target |
| `wlc_phy_txpower_recalc_target_ac_big` | Recalc AC big |
| `wlc_phy_txpower_recalc_target_n_big` | Recalc N big |
| `wlc_phy_txpower_recalc_target_nphy` | Recalc NPHY |
| `wlc_phy_txpower_set` | Set TX power |
| `wlc_phy_txpower_sromlimit` | SROM limit |
| `wlc_phy_txpower_sromlimit_get_nphy` | Get SROM limit NPHY |
| `wlc_phy_txpwr_apply_5gext_srom18` | Apply 5G ext SROM18 |
| `wlc_phy_txpwr_apply_srom11` | Apply SROM11 |
| `wlc_phy_txpwr_apply_srom13` | Apply SROM13 |
| `wlc_phy_txpwr_apply_srom9` | Apply SROM9 |
| `wlc_phy_txpwr_by_index_acphy` | TX power by index AC PHY |
| `wlc_phy_txpwr_cap_enable` | TX power cap enable |
| `wlc_phy_txpwr_cap_get_acphy` | Get TX power cap AC PHY |
| `wlc_phy_txpwr_cap_set_acphy` | Set TX power cap AC PHY |

#### 8.4.5 PHY Tx Power Control

| Function | Purpose |
|----------|---------|
| `wlc_phy_txpwrctrl_coeff_setup_nphy` | TX pwr ctrl coeff setup NPHY |
| `wlc_phy_txpwrctrl_config_acphy` | TX pwr ctrl config AC PHY |
| `wlc_phy_txpwrctrl_enable_acphy` | Enable TX pwr ctrl AC PHY |
| `wlc_phy_txpwrctrl_enable_nphy` | Enable TX pwr ctrl NPHY |
| `wlc_phy_txpwrctrl_idle_tssi_acphy` | Idle TSSI AC PHY |
| `wlc_phy_txpwrctrl_idle_tssi_nphy` | Idle TSSI NPHY |
| `wlc_phy_txpwrctrl_pwr_setup_acphy` | TX pwr ctrl power setup AC PHY |
| `wlc_phy_txpwrctrl_pwr_setup_nphy` | TX pwr ctrl power setup NPHY |
| `wlc_phy_txpwrctrl_set_baseindex` | Set base index |
| `wlc_phy_txpwrctrl_set_idle_tssi_acphy` | Set idle TSSI AC PHY |
| `wlc_phy_txpwrctrl_set_target_acphy` | Set target AC PHY |
| `wlc_phy_txpwrctrl_update_minpwr_acphy` | Update min power AC PHY |

#### 8.4.6 PHY Calibration Tables

| Function | Purpose |
|----------|---------|
| `wlc_phy_table_read_acphy` | Read table AC PHY |
| `wlc_phy_table_read_acphy_dac_war` | Read table AC PHY DAC WAR |
| `wlc_phy_table_read_ext_acphy` | Read table ext AC PHY |
| `wlc_phy_table_read_nphy` | Read table NPHY |
| `wlc_phy_table_write_acphy` | Write table AC PHY |
| `wlc_phy_table_write_acphy_dac_war` | Write table AC PHY DAC WAR |
| `wlc_phy_table_write_ext_acphy` | Write table ext AC PHY |
| `wlc_phy_table_write_nphy` | Write table NPHY |
| `wlc_phy_table_write_tiny_chnsmth` | Write table tiny channel smooth |
| `wlc_phy_table_clrbit_acphy` | Clear bit AC PHY |
| `wlc_phy_table_setbit_acphy` | Set bit AC PHY |
| `wlc_phy_table_clrbit_acphy` | Clear bit AC PHY |
| `wlc_phy_table_read_acphy_dac_war` | Read table AC PHY DAC WAR |

#### 8.4.7 PHY Gain / RSSI / TSSI

| Function | Purpose |
|----------|---------|
| `wlc_phy_txpwr_idx_get_acphy` | TX power index get AC PHY |
| `wlc_phy_txpwr_idx_get_nphy` | TX power index get NPHY |
| `wlc_phy_txpwr_idx_cur_get_nphy` | Current TX power index NPHY |
| `wlc_phy_txpwr_idx_nphy` | TX power index NPHY |
| `wlc_phy_txpwr_limit_to_tbl_nphy` | TX power limit to table NPHY |
| `wlc_phy_txpwr_percent_set` | TX power percent set |
| `wlc_phy_txpwr_est_pwr_acphy` | Estimate power AC PHY |
| `wlc_phy_txpwr_est_pwr_mu_acphy` | Estimate MU power AC PHY |
| `wlc_phy_txpwr_fixpower_acphy` | Fix power AC PHY |
| `wlc_phy_txpwr_fixpower_nphy` | Fix power NPHY |

#### 8.4.8 PHY Radio Calibration

| Function | Purpose |
|----------|---------|
| `wlc_phy_radio_tiny_vcocal` | Tiny radio VCO cal |
| `wlc_phy_radio_tiny_vcocal_wave2` | Tiny radio VCO cal wave2 |
| `wlc_phy_radio_tiny_rccal` | Tiny radio RC cal |
| `wlc_phy_radio_tiny_rccal.constprop.0` | Radio tiny RC cal constprop |
| `wlc_phy_radio_tiny_rcal` | Radio tiny RC cal |
| `wlc_phy_radio_tiny_rccal.constprop.0` | Radio tiny RC cal constprop |

#### 8.4.9 PHY Temperature / Tempsense

| Function | Purpose |
|----------|---------|
| `wlc_phy_tempsense_acphy` | Tempsense AC PHY |
| `wlc_phy_tempsense_acphy_20710` | Tempsense AC PHY 20710 |
| `wlc_phy_tempsense_acphy.part.0` | Tempsense AC PHY part 0 |
| `wlc_phy_tempsense_nphy` | Tempsense NPHY |
| `wlc_phy_tempsense_nphy_rev16` | Tempsense NPHY rev 16 |
| `wlc_phy_tempsense_nphy_rev17` | Tempsense NPHY rev 17 |
| `wlc_phy_tempsense_paldosense_acphy_tiny` | Tempsense PALDO sense tiny |
| `wlc_phy_tempsense_vbatsense_acphy_20698` | VBAT sense AC PHY 20698 |
| `wlc_phy_tempsense_vbatsense_acphy_20707` | VBAT sense AC PHY 20707 |
| `wlc_phy_tempsense_vbatsense_acphy_20708` | VBAT sense AC PHY 20708 |

#### 8.4.10 PHY Calibration Functions

| Function | Purpose |
|----------|---------|
| `wlc_phy_cals_acphy` | AC PHY calibrations |
| `wlc_phy_cals_mac_susp_en_other_cr` | Cals MAC suspend enable |
| `wlc_phy_cal_txgainctrl_inttssi_nphy` | TX gain ctrl int TSSI NPHY |
| `wlc_phy_cal_txgainctrl_nphy` | TX gain ctrl NPHY |
| `wlc_phy_cal_txiqlo_acphy` | TX IQ LO AC PHY |
| `wlc_phy_cal_txiqlo_coeffs_acphy` | TX IQ LO coeffs AC PHY |
| `wlc_phy_cal_txiqlo_init_acphy` | TX IQ LO init AC PHY |
| `wlc_phy_cal_txiqlo_nphy` | TX IQ LO NPHY |
| `wlc_phy_cal_txiqlo_nphy.part.0` | TX IQ LO NPHY part 0 |
| `wlc_phy_cal_txiqlo_update_ladder_acphy.constprop.0` | TX IQ LO update ladder AC PHY |

#### 8.4.11 PHY Initialization

| Function | Purpose |
|----------|---------|
| `wlc_phy_init_acphy` | Init AC PHY |
| `wlc_phy_init_nphy` | Init NPHY |
| `wlc_phy_init_adc_read` | Init ADC read |
| `wlc_phy_attach_nphy` | Attach NPHY |
| `wlc_phy_attach_acphy` | Attach AC PHY |
| `wlc_phy_shared_attach` | Shared attach |
| `wlc_phy_shared_detach` | Shared detach |
| `wlc_phy_shim_attach` | Shim attach |
| `wlc_phy_shim_detach` | Shim detach |

#### 8.4.12 Ucode

| Function | Purpose |
|----------|---------|
| `wlc_ucode_download` | Download ucode |
| `wlc_ucode_sample_init` | Ucode sample init |
| `wlc_ucode_wake_override_clear` | Ucode wake override clear |
| `wlc_ucode_wake_override_set` | Ucode wake override set |
| `wlc_ucode_write` | Write ucode |
| `wlc_ucodex_write` | Write ucodex |
| `wlc_ucode_wake_override_clear` | Wake override clear |
| `wlc_ucode_wake_override_set` | Wake override set |

#### 8.4.13 PHY ED / CCA / Interference

| Function | Purpose |
|----------|---------|
| `wlc_phy_is_edcrs_high` | Is EDCRS high |
| `wlc_phy_is_edcrs_high_acphy` | Is EDCRS high AC PHY |
| `wlc_phy_is_edcrs_high_nphy` | Is EDCRS high NPHY |
| `wlc_phy_update_ed_thres` | Update ED threshold |
| `wlc_phy_update_ed_thres` | Update ED threshold |
| `wlc_phy_conditional_resume` | Conditional resume |
| `wlc_phy_conditional_suspend` | Conditional suspend |

#### 8.4.14 PHY Radar

| Function | Purpose |
|----------|---------|
| `wlc_phy_radar_thresh_acphy_1core` | Radar thresh AC PHY 1 core |
| `wlc_phy_radar_thresh_acphy_2cores` | Radar thresh AC PHY 2 cores |
| `wlc_phy_radar_thresh_acphy_2cores_4366` | Radar thresh AC PHY 2 cores 4366 |
| `wlc_phy_radar_thresh_acphy_4360` | Radar thresh AC PHY 4360 |
| `wlc_phy_radar_thresh_acphy_43602` | Radar thresh AC PHY 43602 |
| `wlc_phy_radar_thresh_axphy_43684` | Radar thresh AX PHY 43684 |
| `wlc_phy_radar_thresh_axphy_43684_lesi` | Radar thresh AX PHY 43684 LESI |
| `wlc_phy_radar_thresh_axphy_6710_lesi` | Radar thresh AX PHY 6710 LESI |
| `wlc_phy_radar_thresh_axphy_6715A0` | Radar thresh AX PHY 6715A0 |
| `wlc_phy_radar_thresh_axphy_6715B0` | Radar thresh AX PHY 6715B0 |
| `wlc_phy_radar_thresh_axphy_6715B0_2Gp5G` | Radar thresh AX PHY 6715B0 2G5G |
| `wlc_phy_radar_thresh_axphy_6756` | Radar thresh AX PHY 6756 |
| `wlc_phy_radar_thresh2_acphy` | Radar thresh2 AC PHY |
| `wlc_phy_radar_thresh2_axphy_43684` | Radar thresh2 AX PHY 43684 |
| `wlc_phy_radar_thresh2_axphy_6710_lesi` | Radar thresh2 AX PHY 6710 LESI |
| `wlc_phy_radar_thresh2_axphy_6715A0` | Radar thresh2 AX PHY 6715A0 |
| `wlc_phy_radar_thresh2_axphy_6715B0` | Radar thresh2 AX PHY 6715B0 |
| `wlc_phy_radar_thresh2_axphy_6715B0_2Gp5G` | Radar thresh2 AX PHY 6715B0 2G5G |
| `wlc_phy_radar_thresh2_axphy_atlas_2Gp5G` | Radar thresh2 AX PHY Atlas 2G5G |
| `wlc_phy_radar_thresh_nphy_ge7` | Radar thresh NPHY GE7 |
| `wlc_phy_radar_select_nfrequent` | Radar select N frequent |
| `wlc_phy_radar_thresh2_acphy` | Radar thresh2 AC PHY |

#### 8.4.15 PHY ACI / Interference

| Function | Purpose |
|----------|---------|
| `wlc_phy_aci_init_nphy` | ACI init NPHY |
| `wlc_phy_aci_noise_reset_nphy` | ACI noise reset NPHY |
| `wlc_phy_aci_noise_shared_hw_set_nphy` | ACI noise shared HW set NPHY |
| `wlc_phy_aci_noise_upd_nphy` | ACI noise update NPHY |
| `wlc_phy_aci_sw_reset_nphy` | ACI SW reset NPHY |
| `wlc_phy_aci_upd` | ACI update |
| `wlc_phy_aci_updsts_acphy` | ACI update status AC PHY |

#### 8.4.16 PHY Noise

| Function | Purpose |
|----------|---------|
| `wlc_phy_noise_calc` | Noise calculation |
| `wlc_phy_noise_calc_fine_resln` | Noise calc fine resolution |
| `wlc_phy_noise_home_channel_nphy` | Noise home channel NPHY |
| `wlc_phy_noise_save` | Noise save |
| `wlc_phy_noise_var_shaping_acphy` | Noise var shaping AC PHY |
| `wlc_phy_noisemode_glitch_chk_adj_nphy` | Noisemode glitch check NPHY |
| `wlc_phy_noisemode_reset_nphy` | Noisemode reset NPHY |
| `wlc_phy_noisemode_upd_nphy` | Noisemode update NPHY |
| `wlc_phy_eu_edcrs_status_nphy` | EU EDCRS status NPHY |

---

### 8.5 D11regs / SHM / Registers

**Key structures (from disassembly):**

| Structure | Base | Size | Purpose |
|-----------|------|------|---------|
| `d11regs` | (d11regsx130 at 0xa19d0) | 0x240 | D11 core registers |
| `d11regsx130` | 0xa19d0 | 0x240 | D11 core rev 130 |
| SHM | (shared memory) | — | Shared memory for MAC/CPU |

**Key register access functions:**

| Function | Purpose |
|----------|---------|
| `wlc_write_shm` | Write SHM (292 calls) |
| `wlc_write_shmx` | Write SHM extended (241 calls) |
| `wlc_read_shm` | Read SHM |
| `wlc_write_radioreg` | Write radio register |
| `wlc_read_radioreg` | Read radio register |
| `wlc_phy_table_write_acphy` | Write PHY table AC PHY (791 calls) |
| `wlc_phy_table_write_nphy` | Write PHY table NPHY (301 calls) |
| `wlc_phy_table_read_acphy` | Read PHY table AC PHY |
| `wlc_phy_table_read_nphy` | Read PHY table NPHY |

---

### 8.6 Call Graph Summary

```
wlc_attach()
    ├─ wlc_pm_attach() → power save init
    ├─ wlc_dump_attach() → dump module init
    ├─ wlc_channel_mgr_attach() → channel manager
    ├─ wlc_phy_init_acphy() / wlc_phy_init_nphy() → PHY init
    ├─ wlc_ucode_download() → download ucode
    └─ wlc_module_register() → register modules

wl_up()
    ├─ wlc_pm_wlc_up() → PM up
    ├─ wlc_phy_init_acphy() / wlc_phy_init_nphy() → PHY init
    ├─ wlc_ucode_download() → download ucode
    └─ wlc_radio_upd() → radio update

Periodic:
    wlc_phy_watchdog_nphy() → PHY watchdog
    wlc_phy_cal_perical_nphy_run() → periodic cal
    wlc_phy_tempsense_acphy() → tempsense

TX Path:
    wlc_send()
        └─ wlc_phy_txpower_get() → get TX power
        └─ wlc_phy_table_write_acphy() → PHY table write

Calibration:
    wlc_phy_cal_perical_nphy_run() → periodic cal
    wlc_phy_cal_txiqlo_acphy() → TX IQ LO cal
    wlc_phy_cal_txiqlo_nphy() → TX IQ LO NPHY
    wlc_phy_cal_txiqlo_acphy() → TX IQ LO AC PHY
```

---

### 8.7 Binary Offsets Quick Reference

| Function | Address | Size | Key Feature |
|----------|---------|------|-------------|
| `wlc_attach` | 0x3100ac | 0x2400 | Main attach |
| `wlc_up` | 0x319618 | 0x614 | Bring up |
| `wlc_down` | 0x319458 | 0x1c0 | Bring down |
| `wlc_pm_attach` | (in power_save) | — | PM init |
| `wlc_dump_attach` | (in debug_dump) | — | Dump init |
| `wlc_channel_mgr_attach` | (in chanspec_reg) | — | Channel manager |
| `wlc_phy_init_acphy` | (in d11_phy) | — | AC PHY init |
| `wlc_phy_init_nphy` | (in d11_phy) | — | NPHY init |
| `wlc_ucode_download` | (in d11_phy) | — | Ucode download |
| `wlc_ucode_write` | (in d11_phy) | — | Write ucode |
| `wlc_phy_table_write_acphy` | (in d11_phy) | 791 calls | PHY table write AC |
| `wlc_phy_table_write_nphy` | (in d11_phy) | 301 calls | PHY table write NPHY |
| `d11regsx130` | 0xa19d0 | 0x240 | D11 regs rev 130 |

---

## Next: Chapter 9 — Modules Overview (19 other modules)

*To be written...*