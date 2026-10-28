# OWA7111VDF / driver_extract — kernel module index

Extract from the rooted extender (BCM6756_A1, Homeware 22.1-0022-6381007,
machine name `GDNT-M`). 20 loadable kernel modules, ARM32 ELF relocatables
(`e_machine=ARM`, `e_type=ET_REL`), built for kernel
`4.19.208 SMP preempt mod_unload ARMv7 p2v8`, PKCS#7-signed.

Generated on 2026-10-28 by `/tmp/opencode/wlindex/scan.py`
(binutils 2.46 + kmod modinfo via ad-hoc nix shell; scoping: goal `c0bf6697`).
Raw per-module dumps: `/tmp/opencode/wlindex/*.txt`
and `modules.json` (defined/undefined symbols, strings, section headers).

## At a glance

| Module | Size | License | Deps | Defined syms |
|---|---:|---|---|---:|
| wl.ko | 11.8 MB | Proprietary | hnd,wlshared,bcmlibs,emf,cfg80211,igs | 13010 |
| hnd.ko | 471 KB | GPL + add. rights | bcm_knvram | 2922 |
| dhd.ko | 1.18 MB | GPL + add. rights | hnd,cfg80211,wlshared,bcm_knvram,bcmlibs,bcmmcast,emf,igs | 3425 |
| pktflow.ko | 329 KB | Proprietary | bcmlibs | 958 |
| bcmvlan.ko | 137 KB | Proprietary | – | 372 |
| archer.ko | 258 KB | Proprietary | cmdlist,bcm_archer_gpl,bcmlibs,bcm_ingqos,pktflow | 535 |
| bcm_enet.ko | 220 KB | GPL | bcmlibs,bcm_archer_gpl | 618 |
| bcm_pcie_hcd.ko | 110 KB | GPL | bcm_knvram | 369 |
| ripdrv.ko | 48 KB | GPL | tomcrypt,tommath,platform | 181 |
| bcm_bpm.ko | 49 KB | (none in modinfo) | – | 211 |
| bcmlibs.ko | 45 KB | GPL | – | 279 |
| nat46.ko | 44 KB | GPL | nf_defrag_ipv6 | 166 |
| bcm_ingqos.ko | 41 KB | GPL | – | 188 |
| emf.ko | 25 KB | Dual MIT/GPL | hnd,bcmmcast | 125 |
| bcm_license.ko | 27 KB | Proprietary | – | 102 |
| bcm_archer_gpl.ko | 19 KB | GPL | – | 107 |
| bcm_thermal.ko | 13 KB | GPL | – | 65 |
| bcm_knvram.ko | 14 KB | GPL | – | 55 |
| wlshared.ko | 8.8 KB | GPL + add. rights | – | 51 |
| igs.ko | 33 KB | Dual MIT/GPL | emf,hnd,bcmmcast | 124 |

Functional grouping:

- **Wi-Fi core** — `wl.ko` (PCI `bc02sc80i` arch, 13k named functions, full wlc_*)
- **Wi-Fi support** — `hnd.ko` (shared Broadcom network driver layer, 2922 syms),
  `wlshared.ko` (BSP/WLAN glue), `dhd.ko` (dongle/HSD/HSIC Wi-Fi driver — a second full
  wireless stack used for USB/PCIe dongles, probably not the wl interface of this board)
- **Ethernet / offload** — `archer.ko` + `bcm_archer_gpl.ko` (Archer network processor),
  `bcm_enet.ko`, `pktflow.ko` (packet flow cache), `bcm_bpm.ko` (buffer pool mgmt),
  `bcm_ingqos.ko`, `bcmlibs.ko`, `bcmvlan.ko`
- **Platform** — `bcm_pcie_hcd.ko`, `bcm_knvram.ko` (NVRAM access used by hnd/wl),
  `bcm_license.ko`, `bcm_thermal.ko`, `ripdrv.ko` (RIP record reader — this is the
  previously-root-board /proc/rip/012f path; depends on the tomcrypt/tommath/platform
  chain loaded at boot)
- **Networking helpers** — `nat46.ko` (stateless NAT46), `emf.ko` (multicast forwarding),
  `igs.ko` (IGMP snooping)

## Dependency graph (module layer)

```
wl ──────┬─▶ hnd ────▶ bcm_knvram
         ├─▶ wlshared
         ├─▶ bcmlibs
         ├─▶ emf ─────▶ hnd, bcmmcast
         ├─▶ cfg80211 (core kernel)
         └─▶ igs ─────▶ emf, hnd, bcmmcast
dhd ─────▶ hnd, cfg80211, wlshared, bcm_knvram, bcmlibs, bcmmcast, emf, igs
archer ──▶ cmdlist, bcm_archer_gpl, bcmlibs, bcm_ingqos, pktflow
bcm_enet ▶ bcmlibs, bcm_archer_gpl
pktflow ─▶ bcmlibs
ripdrv ──▶ tommcrypt, tompcrypt2, platform   (the 3 already-insmod'ed deps on the live board)
nat46 ───▶ nf_defrag_ipv6
```

(Entries whose deps are not in driver_extract — `bcmmcast`, `cmdlist`, `cfg80211`,
`platform`, `tomcrypt`, `tommath`, `nf_defrag_ipv6` — are provided by the rootfs /
kernel directly or in separate modules not captured.)

## Reversing notes

- Every `.ko` here is **unstripped**: `nm` yields full symbol names with sizes.
  This means function boundaries are already known and the main analysis is
  meaning-assignment, not partitioning.
- All modules are ARM 32-bit; wl.ko is the big target (BCN/RSN/security stack).
- usr-src anchors to hunt for: this is a Broadcom stack similar to
  Samsung-arch-embedded-Open-Source / Homeware GPL dumps. Known families to try:
  `wlioctl.h`, `wl.c`, `wlc_lq`, `wlc_bcn*`, `wlc_akm_*`, `wlc_wpa_*`,
  `wl_wsec_info` — all these names appear as symbols in wl.ko.

## Key namespaces found in wl.ko (for the beacon/priv-bit hunt)

- `wlc_bcn_prb_template`, `wlc_bcn_prb_body`, `wlc_bcn_write_*_ie`,
  `wlc_bcn_calc_*_ie_len`, `wlc_bcn_li_upd`, `wlc_bcn_register_iem_fns`
- `wlc_akm_bcn_write_osen_rsn_ie`, `wlc_akm_bcn_calc_wpa_ie_len`,
  `wlc_akm_calc_rsn_ie_len`, `wlc_akm_arsp_write_rsn_ie`, …
- `bcmwpa_*` (helpers), `bcm_encode_ie_extended_capabilities`,
  `bcm_decode_ie_extended_capabilities`
- `km_iov_get/set_wsec_*` (key-management ioctl handlers — correlates with
  `wsec_info` 0x0104/0x0105 reads from the board)

*(addresses recorded in `/tmp/opencode/wlindex/wl.ko.defined.txt`)*

## Open questions driving the next phase

1. Where do `wpa_auth 0x80` + `wsec 4` + `addwep ... ccm` get routed in wl.ko —
   is the beacon's fixed `capabilities` Privacy bit assembled from a stale
   `bsscfg` snapshot vs live `wsec` state?
2. Locate the beacon template writer (`wlc_bcn_prb_template`) and find the
   capabilities byte assembly + its gating condition.
3. Confirm via source-matching dumps (Samsung/Broadcom GPL dumps of similar
   `wlc_akm_bcn*` code) and cross-check each source claim against binary strings.
