# OWA7111VDF Driver Stack — 19 Other Modules Overview

**Device:** OWA7111VDF extender, BCM6756_A1, Homeware 22.1-0022-6381007, kernel 4.19.208  
**Source:** Binary analysis of 20 ARM32 `.ko` modules from `/home/user/OWA7111VDF/driver_extract/`  
**Method:** Desk-only reverse engineering; no board access. Symbol tables, strings, and cross-references used for classification.

---

## 1. dhd.ko — Dongle/HSD Host Driver (3,425 symbols / 2,389 unique functions)

**Purpose:** Full-featured dongle/HSD (High Speed Data) host driver for Broadcom Wi-Fi dongles. Implements the dongle-side protocol, bus abstraction (SDIO/PCIe), flow ring management, and cfg80211 glue for Linux kernel integration.

**Dependency Role:** Independent Wi-Fi stack parallel to `wl.ko` — used for USB/SDIO/PCIe dongles. On OWA7111VDF, `wl.ko` handles the SoC-integrated radio (SB bus) while `dhd.ko` would handle external dongles (if present).

**Key Exports (2,389 unique functions, 3,425 total symbols):**

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Core dhd** | `dhd_` | 700 | `dhd_attach`, `dhd_detach`, `dhd_bus_*` (DPC, watchdog, flow rings), `dhd_cfg80211_*`, `dhd_awl_*` |
| **PCIe Bus** | `dhdpcie_` | 64 | `dhdpcie_bus_attach`, `dhdpcie_bus_cfg_read/write_dword`, `dhdpcie_bus_db1_ringbell_2`, `dhdpcie_bus_intr_enable/disable`, `dhdpcie_bus_doiovar` |
| **Flow Rings** | `dhd_bus_flow_ring_` | ~20 | `create/delete/flush_request/response` for H2D/D2H rings |
| **Aggregation** | `dhd_aggr_` | ~10 | `dhd_aggr_init/deinit`, `add/del_aggregator`, `intercept` |
| **PCIe Bus Ops** | `dhd_bus_` | ~15 | `dhd_bus_cfg_read/write`, `dhd_bus_ringbell*`, `dhd_bus_txdata`, `dhd_bus_txqueue_*`, `dhd_bus_watchdog` |
| **cfg80211 Glue** | `dhd_cfg80211_` | ~10 | `dhd_cfg80211_init/deinit/up/down`, `dhd_cfg80211_set_p2p_info` |
| **AWL (Airtime Weighted Latency)** | `dhd_awl_` | ~20 | `dhd_awl_attach/detach`, `dhd_awl_rx_flow_miss_handler_*`, `dhd_awl_upstream` |
| **L2 Filter** | `bcm_l2_filter_` | ~15 | `bcm_l2_filter_parp_*`, `bcm_l2_filter_block_ping`, `bcm_l2_filter_gratuitous_arp` |
| **WET (Wireless Ethernet Tunnel)** | `wet_` | 23 | `wet_arp/dhcp/icmp/ip/ipv6_proc` |
| **wldev** | `wldev_` | 24 | `wldev_ioctl_get/set`, `wldev_iovar_getbuf/set`, `wldev_get_*` |
| **Packet Management** | `pktpool`/`pktq`/`spktq`/`nbuff` | 65+ | Packet allocation, queue management, flow IDs |
| **Bus Interface** | `dhdpcie_bus_` | 64 | PCIe-specific: `cfg_read/write_dword`, `ringbell`, `intr_enable/disable`, `db1_ringbell` |
| **cfg80211 Vendor** | `dhd_cfgvendor_` | ~5 | `dhd_cfgvendor_priv_string_handler` |
| **Config/State** | `dhd_bus_` | ~15 | `dhd_bus_attach/detach`, `start/stop`, `dpc`, `intr_enable/disable`, `txdata` |
| **Firmware Download** | `dhd_bus_download_firmware` | 1 | Firmware download to dongle |
| **cfg80211 Vendor Commands** | `dhd_cfgvendor_` | ~5 | Vendor command dispatch |

**Integration Points with wl.ko/hnd.ko:**
- **Bus Layer:** Uses `hnd.ko` silicon backplane (`si_*`, `ai_*`) for register access
- **Packet Pools:** Uses `hnd.ko` `pktpool_*` and `osl_*` for packet allocation
- **DMA:** Uses `hnd.ko` `osl_dma_*` for consistent DMA mappings
- **PCIe:** Uses `hnd.ko` `si_pcie_*` and `osl_pcie_*` for PCIe config space
- **NVRAM/OTP:** Uses `hnd.ko` `si_nvram_*`, `otp_*`, `srom_*`
- **Timer/Event:** Uses `hnd.ko` timer/event subsystem

**Key Differences from wl.ko:**
- `dhd.ko` is a **dongle host driver** (USB/SDIO/PCIe) — communicates with external dongle firmware
- `wl.ko` is a **SoC-integrated driver** (SB bus) — directly controls on-chip radio
- `dhd.ko` implements **flow ring** DMA architecture; `wl.ko` uses direct SB register access
- `dhd.ko` has full **cfg80211 vendor command** support; `wl.ko` uses legacy `wlioctl` interface

---

## 2. hnd.ko — Shared Network Driver Layer (2,922 symbols)

**Purpose:** Hardware abstraction layer (HAL) for Broadcom silicon backplane. Provides core access, DMA, timer, packet pool, NVRAM/OTP/SROM, PCIe/PCI, and OS abstraction (osl).

**Dependency Role:** Foundation layer — required by both `wl.ko` and `dhd.ko`.

**Key Exports (2,922 symbols):**

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Core Access (AI)** | `ai_` | ~30 | `ai_coreaddrspaceX`, `ai_corereg`, `ai_corereg_addr`, `ai_core_reset`, `ai_setcoreidx`, `ai_scan` |
| **Silicon Backplane (SI)** | `si_` | ~100 | `si_attach`, `si_core_disable`, `si_coreaddrspaceX`, `si_corereg`, `si_pcie_*`, `si_pmu_*`, `si_gci_*` |
| **PMU** | `pmu_` | ~50 | `pmu_attach`, `pmu_pll_init`, `pmu_otp_*`, `pmu_res_*`, `pmu_spuravoid`, `pmu_wait_for_steady_state` |
| **PCIe** | `pcie_`/`si_pcie_` | ~60 | `pcie_configspace_*`, `pcie_dma_*`, `si_pcie_*`, `pcie_war_*` |
| **DMA** | `osl_dma_` | ~10 | `osl_dma_alloc/free_consistent`, `osl_dma_map/unmap/sync` |
| **Packet Pool** | `pktpool_` | ~20 | `pktpool_init/deinit`, `pktpool_avail_*`, `pktpool_fill`, `pktpool_rxcplid_fill_register` |
| **Packet Queue** | `pktq_`/`spktq_` | ~40 | `pktq_*`, `spktq_*` |
| **Network Buffers** | `nbuff_` | ~25 | `nbuff_pktalloc`, `nbuff_pktfree`, `nbuff_pktdup`, `nbuff_pktpush/pull` |
| **NVRAM/OTP/SROM** | `nvram_`/`otp_`/`srom_` | ~30 | `nvram_*`, `otp_*`, `srom_*`, `si_srom_*` |
| **PCI/PCIE** | `si_pci_`/`si_pcie_` | ~30 | `si_pci_up/down`, `si_pcie_*`, `si_pciedev_*` |
| **Utility (bcm_*)** | `bcm_` | 112 | String, math, crypto, TLV, IP checksum, CRC, bit ops |
| **Math/Crypto** | `math_`/`hndcrc` | ~30 | `math_cmplx_*`, `math_fp_*`, `math_fft_*`, `hndcrc8/16/32` |
| **Crypto Algo** | `bcm_crypto_` | 2 | `bcm_crypto_algo_name` |
| **OS Abstraction (osl)** | `osl_` | 57 | `osl_attach/detach`, `osl_malloc/free`, `osl_pkt*`, `osl_dma_*`, `osl_pci_*`, `osl_delay`, `osl_sleep` |
| **Timer/DLL Pool** | `dll_pool_` | ~5 | `dll_pool_alloc/detach/free/init` |
| **CRC** | `hndcrc` | 3 | `hndcrc8/16/32` |
| **Module Lifecycle** | `init_module`/`cleanup_module` | 2 | Kernel module entry/exit |

**Integration Points:**
- **wl.ko:** Calls `si_attach`, `ai_corereg`, `pmu_*`, `osl_dma_*`, `osl_pkt*`, `pktpool_*`, `si_pcie_*`, `si_gci_*`
- **dhd.ko:** Same HND layer; uses `osl_*`, `si_*`, `ai_*`, `pmu_*`, `pktpool_*`, `nvram_*`, `otp_*`, `srom_*`

---

## 3. archer.ko + bcm_archer_gpl.ko — Archer Network Processor (258 + 19 KB)

**Purpose:** Archer Network Processor (NP) offload engine for traffic management, flow classification, and QoS.

**Dependency Role:** Offload engine — works with `bcm_enet.ko` and `pktflow.ko`.

| Module | Size | Symbols | Key Exports |
|--------|------|---------|-------------|
| `archer.ko` | 258 KB | 535 | Archer NP command processing, flow management, packet classification |
| `bcm_archer_gpl.ko` | 19 KB | 107 | GPL wrapper for Archer NP |

**Integration:** Depends on `bcm_enet.ko`, `bcmlibs.ko`, `bcm_ingqos.ko`, `pktflow.ko`, `bcm_bpm.ko`. Uses `hnd.ko` `osl_*` and `pktpool_*`.

---

## 4. bcm_enet.ko + bcmvlan.ko + bcm_bpm.ko + bcm_ingqos.ko + pktflow.ko — Ethernet Offload Stack

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_enet.ko` | 220 KB | 618 | Ethernet MAC driver, GMAC/RGMII/SGMII, MII management |
| `bcmvlan.ko` | 137 KB | 372 | VLAN filtering, 802.1Q, VLAN translation |
| `bcm_bpm.ko` | 49 KB | 211 | Buffer Pool Manager — packet buffer allocation |
| `bcm_ingqos.ko` | 41 KB | 188 | Ingress QoS, traffic classification, policing |
| `pktflow.ko` | 329 KB | 958 | Packet Flow Cache — fast path forwarding, flow hashing |

**Integration Chain:** `pktflow.ko` → `bcm_enet.ko` → `bcmvlan.ko` → `bcm_bpm.ko` + `bcmlibs.ko` + `bcm_ingqos.ko` → `hnd.ko` (osl, pktpool, dma)

---

## 5. bcm_pcie_hcd.ko + bcm_knvram.ko + bcm_license.ko + bcm_thermal.ko — Platform Drivers

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_pcie_hcd.ko` | 110 KB | 369 | PCIe Host Controller Driver — MSIX, MSI, BAR management |
| `bcm_knvram.ko` | 14 KB | 55 | Kernel NVRAM access — used by `hnd.ko` `nvram_*` |
| `bcm_license.ko` | 27 KB | 102 | License management, feature enablement |
| `bcm_thermal.ko` | 13 KB | 65 | Thermal management, temperature monitoring |

---

## 6. bcmlibs.ko + wlshared.ko + emf.ko + igs.ko + nat46.ko + ripdrv.ko — Support Libraries

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcmlibs.ko` | 45 KB | 279 | Core Broadcom library — string, math, crypto, data structures |
| `wlshared.ko` | 8.8 KB | 51 | WL shared glue — common structures between `wl.ko` and `dhd.ko` |
| `emf.ko` | 25 KB | 125 | Ethernet Multicast Forwarding — IGMP/MLD snooping |
| `igs.ko` | 33 KB | 124 | IGMP Snooping — multicast group management |
| `nat46.ko` | 44 KB | 166 | NAT46 — IPv4/IPv6 translation |
| `ripdrv.ko` | 48 KB | 181 | RIP Record Driver — accesses `/proc/rip` for board info |

---

## 7. bcm_license.ko — License Manager

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_license.ko` | 27 KB | 102 | Feature licensing, capability enablement |

---

## 8. bcm_thermal.ko — Thermal Management

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_thermal.ko` | 13 KB | 65 | Temperature monitoring, thermal throttling |

---

## 9. bcm_knvram.ko — Kernel NVRAM

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_knvram.ko` | 14 KB | 55 | Kernel NVRAM access layer |

---

## 10. bcmmcast.ko (referenced in INDEX.md)

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcmmcast.ko` | (referenced) | — | Multicast forwarding support |

---

## 11. bcm_archer_gpl.ko

| Module | Size | Symbols | Purpose |
|--------|------|---------|---------|
| `bcm_archer_gpl.ko` | 19 KB | 107 | GPL Archer NP wrapper |

---

## Dependency Graph Summary

```
hnd.ko (foundation)
├── wl.ko (SoC radio) ← ai_*, si_*, pmu_*, osl_*, pktpool_*, si_pcie_*
├── dhd.ko (dongle/HSD) ← si_*, ai_*, pmu_*, osl_*, pktpool_*, nvram/otp/srom
├── archer.ko + bcm_archer_gpl.ko
│   ├── bcm_enet.ko
│   ├── bcmvlan.ko
│   ├── bcm_bpm.ko
│   ├── bcm_ingqos.ko
│   └── pktflow.ko
├── bcm_enet.ko
├── bcmvlan.ko
├── bcm_bpm.ko
├── bcm_ingqos.ko
├── pktflow.ko
├── bcm_pcie_hcd.ko
├── bcm_knvram.ko
├── bcm_license.ko
├── bcm_thermal.ko
├── bcmlibs.ko
├── wlshared.ko
├── emf.ko
├── igs.ko
├── nat46.ko
├── ripdrv.ko
└── bcmmcast.ko (referenced)
```

---

## Integration Points Summary

| Module | Depends On | Provides To |
|--------|------------|-------------|
| **hnd.ko** | (kernel) | `wl.ko`, `dhd.ko`, `archer.ko`, `bcm_enet.ko`, `pktflow.ko`, `bcm_pcie_hcd.ko`, `bcmlibs.ko`, `bcm_knvram.ko` |
| **wl.ko** | `hnd.ko` | (AP/STA radio) |
| **dhd.ko** | `hnd.ko` | (Dongle/HSD radio) |
| **archer.ko** | `hnd.ko`, `bcm_enet.ko`, `bcm_ingqos.ko`, `pktflow.ko`, `bcm_bpm.ko`, `bcmlibs.ko` | (NP offload) |
| **bcm_enet.ko** | `hnd.ko`, `bcmlibs.ko`, `bcm_archer_gpl.ko` | `bcmvlan.ko`, `pktflow.ko` |
| **pktflow.ko** | `hnd.ko`, `bcmlibs.ko`, `bcm_enet.ko`, `bcm_bpm.ko` | (Fast path) |
| **bcmlibs.ko** | `hnd.ko` (osl) | All modules (utils) |
| **wlshared.ko** | `hnd.ko` | `wl.ko`, `dhd.ko` (shared structs) |
| **emf/igs** | `hnd.ko`, `bcmlibs.ko` | Multicast/IGMP |
| **ripdrv.ko** | `hnd.ko` (tomcrypt/tommath/platform) | `/proc/rip` access |

---

*Generated by desk-only reverse engineering of OWA7111VDF driver_extract/. No board access performed.*