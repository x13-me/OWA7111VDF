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

## 3. archer.ko + bcm_archer_gpl.ko — Archer Network Processor (Deep)

**Purpose:** Archer Network Processor (NP) offload engine for traffic management, flow classification, DMA-based packet steering between Ethernet and Wi-Fi domains, and QoS. Implements DMA descriptor rings, socket-based control interface, CPU TX/RX task handlers, and WLAN bind hooks for steering traffic between `bcm_enet.ko` and `wl.ko`.

**Size:** `archer.ko` 258 KB (535 syms / 91 undef) | `bcm_archer_gpl.ko` 19 KB (107 syms / 44 undef)
**Depends on:** `cmdlist`, `bcm_archer_gpl`, `bcmlibs`, `bcm_ingqos`, `pktflow` | `bcm_archer_gpl.ko` has no module deps.

### archer.ko Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **DMA** | `archer_dma_*` | 11 | `archer_dma_buffer_construct`, `archer_dma_setup`, `archer_dma_rx_isr`, `archer_dma_transmit_enet`, `archer_dma_task_cpu_tx`, `archer_dma_task_rx_handler`, `archer_dma_flush_tx_ring_by_context` |
| **Socket / Control** | `archer_socket_*` | 6 | `archer_socket_alloc`, `archer_socket_construct`, `archer_socket_free`, `archer_socket_run`, `archer_socket_task_handler` |
| **DHD (dongle host) interface** | `archer_dhd_*` | 18 | `archer_dhd_construct`, `archer_dhd_isr`, `archer_dhd_cpu_rx_queue_write`, `archer_dhd_flow_ring_dump`, `archer_dhd_tx_complete_task_handler`, `archer_dhd_rx_complete_task_handler`, `archer_dhd_tx_coalescing_*` |
| **WLAN bind** | `archer_wlan_*` | 21 | `archer_wlan_bind_hook`, `archer_wlan_construct`, `archer_wlan_rx_register_hook`, `archer_wlan_rx_send_hook`, `archer_wlan_tx_packet_int`, `archer_wlan_tx_dev_name_int`, `archer_wlan_tx_task_handler`, `archer_wlan_unbind_hook`, `archer_wlan_flctl_config_get/set` |
| **Sysport** | `sysport_*` | 96 | `sysport_driver_user_irq`, `sysport_classifier_flow`, plus Archer NP sysport command processing |
| **Memory / Coherent** | `archer_mem_*`, `archer_coherent_mem_*` | ~10 | `archer_coherent_mem_alloc`, `archer_coherent_mem_free`, `archer_mem_*` |
| **DPI / flow** | `archer_dpi_*`, `archer_flow_*` | ~10 | DPI classification, flow activation |

### bcm_archer_gpl.ko — GPL Wrapper

**Purpose:** GPL-licensed shim that exposes Archer NP to the Linux netdevice stack. Registers a netdevice (`archer_create_netdevice`, `archer_dev_open`, `archer_dev_start_xmit`, `archer_dev_change_mtu`), binds to Ethernet (`archer_gpl_enet_bind`/`archer_gpl_enet_config`), manages coherent memory, and handles DSL init.

**Key Exports:** `archer_gpl_enet_bind`, `archer_gpl_enet_config`, `archer_coherent_mem_alloc/free`, `archer_construct/destruct`, `archer_gpl_dsl_init`, `archer_host_bind`.

### Integration Points
- **Consumes from:** `pktflow.ko` (flow cache), `bcm_enet.ko` (Ethernet port RX/TX via `archer_enet_*` hooks), `bcm_ingqos.ko` (ingress QoS), `bcm_bpm.ko` (buffer pool), `bcmlibs.ko` (bitmaps/pktqueue), `hnd.ko` (`osl_*`, `pktpool_*`)
- **Provides to:** `bcm_archer_gpl.ko` (netdevice shim), `wl.ko`/`dhd.ko` (WLAN traffic steering via `archer_wlan_*` bind hooks)
- **Cross-references:** Strings show `archer_mcast_activate`, `archer_ucast_activate`, `archer_dhd_buffer_alloc` — ties into `pktflow` multicast and `dhd` flow rings

### Notable Strings (evidence)
- `"Could not archer_dma_alloc_pkt_desc_ring"` — DMA ring allocation
- `"archer_dhd_index_pool_full()"` — DHD index pool assertion
- `"Could not archer_gpl_dsl_init"` / `"Could not archer_gpl_sysport_init"` — GPL wrapper init paths

---

---

## 4. pktflow.ko — Packet Flow Cache (Deep)

**Purpose:** Broadcom Packet Flow Cache — Layer-2/Layer-3 fast-path forwarding cache. Maintains flow hash tables, forwards packets by flow, supports hardware-accelerated offload (NPE — Network Processor Engine), multicast group management, FDB (forwarding database) learning/aging, and per-path statistics. On OWA7111VDF this is the Ethernet fast path that `bcm_enet.ko` feeds packets into.

**Size:** 329 KB | **Symbols:** 958 defined / 159 undefined | **Depends on:** `bcmlibs`

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Flow Core** | `fc_` | 169 | `fc_alloc_flow`, `fc_activate_flow_fhw`, `fc_deactivate_fhw`, `fc_flush_flows`, `fc_evict_flow`, `fc_config`, `fc_bind_fhw`, `fc_bind_blog`, `fc_clear`, `fc_dev_xmit`, `fc_getflwstats`, `fc_fdb_*` |
| **Flow Cache** | `fcache_` | 97 | `fcache_construct`, `fcache_destruct`, `fcache_dump_flow_info`, `fcache_dump_flow_blog_info`, `fcache_error_stats_print`, `fcache_evict_stats_print`, `fcache_evt_flush_flows`, `fcache_evt_flush_fdb`, `fcache_evt_flush_npe`, `fcache_drv_mcast_*_procfs` |
| **Path / PathDB** | `path*` | 31 | `path_add_flow`, `path_build_hash_key`, `path_calc_hash`, `path_create_path`, `path_delete_path`, `path_evict_flow`, `path_hash_search`, `path_flush_hw_stats` |
| **Fast-HW (NPE)** | `fhw_*` | 31 | `fc_chk_hw_support_fhw`, `fc_bind_fhw`, `fc_activate_fhw`, `fc_deactivate_fhw`, `fc_flush_hw`, `path_fhw_alloc` |
| **Procfs / Debug** | `fcacheDrv_*`, `pathstatDrv_*` | 16 | `/proc` entries for flow stats, mcast group info, NPE info |
| **FDB** | `fc_fdb_*` | 8 | `fc_fdb_add_to_list`, `fc_fdb_get`, `fc_fdb_hashin`, `fc_fdb_rem_from_list`, `fc_fdb_upd_time` |

### Key Data Structures / Concepts (string-anchored)
- `FCACHE_MAX_MCAST_GROUPS` / `FCACHE_MAX_MCAST_FLOW_ENTRIES` / `FCACHE_MAX_MCAST_CLIENTS` — multicast scale limits
- `mcast FcacheMcastXmitInfo_t` — multicast transmit info structure
- Hybrid mcast path: `fkb_clone` / `fkb_unshare` — cloned sk_buff handling for multicast replication
- Flow hash key built from 5-tuple (`path_build_hash_key`, `path_calc_hash`)
- NPE (Network Processor Engine) offload via `fhw_*` functions

### Integration Points
- **Consumes from:** `bcm_enet.ko` (ingress packets via `enetxapi_*` RX path), `bcmlibs.ko` (bitmaps, pktqueue, pktlist, d3lut)
- **Provides to:** `archer.ko` (Archer NP offload hooks), `bcmvlan.ko` (VLAN-tagged flow handling)
- **Hooks into `hnd.ko`:** uses `osl_*`, `pktpool_*`, DMA for packet buffers
- **Procfs:** exposes flow/mcast/NPE stats under `/proc` via `fcacheDrv_*` seq_ops

### Notable Strings (evidence)
- `"FCACHE ERROR: ... _fc_group_htable_ent(%u,%u,%u) find failure"` — group hash table lookup
- `"mcast fkb_clone failed"` / `"mcast fkb_unshare failed"` — multicast skb cloning
- `"Could not archer_mcast_activate"` / `"Could not archer_ucast_activate"` — cross-references into `archer.ko` activation hooks

---

## 4b. bcm_enet.ko — Ethernet MAC Driver (Deep)

**Purpose:** Broadcom internal Ethernet network driver for BCM6756. Drives the GMAC/RGMII/SGMII MAC, MII management, switch fabric (SF2), port configuration, ethtool, and the `ioctl_extsw` extended switch interface. Source path anchors: `../../bcmdrivers/opensource/net/enet/bcm96756/archer_enet.c` and `bcmenet_ioctl_compat.c`.

**Size:** 220 KB | **Symbols:** 618 defined / 181 undefined | **Depends on:** `bcmlibs`, `bcm_archer_gpl`

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Port** | `port_*` | 47 | `port_activate`, `port_deactivate`, `port_config`, `port_create`, `port_by_netdev`, `port_by_port_id`, `port_attr_get/set`, `port_arl`, `port_command_table`, `port_cnt`, `port_count` |
| **MAC / enet** | `enet_*` | 46 | `bcm_enet_init`, `bcm_enet_exit`, `bcm_enet_init_post`, `bcm_link_handler_config`, `bcm_tcp_v4_recv`, `enet_open`, `enet_stop`, `enet_hard_start_xmit` |
| **Switch Fabric (SF2)** | `sf2_*` | 16 | `sf2_config`, `sf2_port_init`, `sf2_port_mac`, `sf2_sw_config_trunk`, `sf2_led_config`, `sf2_lan`, `sf2_fc_configured`, `sf2_fc_info` |
| **Extended Switch Ioctl** | `ioctl_extsw_*` | 29 | `ioctl_extsw_control`, `ioctl_extsw_info`, `ioctl_extsw_vlan`, `ioctl_extsw_pbvlan`, `ioctl_extsw_port_irc_get/set`, `ioctl_extsw_port_mirror_ops`, `ioctl_extsw_port_trunk_ops`, `ioctl_extsw_dos_ctrl`, `ioctl_extsw_cosq_*`, `ioctl_extsw_dscp_to_priority_mapping` |
| **enetxapi (offload API)** | `enetxapi_*` | 14 | `enetxapi_rx_pkt`, `enetxapi_post_config`, `enetxapi_post_parse`, `enetxapi_post_sf2_config/parse`, `enetxapi_queue_int_disable/enable`, `enetxapi_buf_recycle`, `enetxapi_fkb_databuf_recycle` |
| **bcm63xx ethtool** | `bcm63xx_ethtool_*` | 16 | `bcm63xx_ethtool_get_drvinfo`, `get/set_ksettings`, `get/set_pauseparam`, `get/set_eee`, `get_module_eeprom/info` |
| **bcmenet (shared)** | `bcmenet_*` | 12 | `bcmenet_fullname`, `bcmenet_vers`, `bcmenet_is_wan_port`, `bcmenet_is_bonded_lan_wan_port`, `bcmenet_lag_port_get`, `bcmenet_sysport_config` |

### Integration Points
- **Consumes from:** `bcmlibs.ko` (utils), `bcm_archer_gpl.ko` (Archer NP binding via `archer_gpl_enet_bind`/`config`)
- **Provides to:** `pktflow.ko` (RX packets via `enetxapi_rx_pkt`), `archer.ko` (via `archer_enet_*` hooks: `archer_enet_rx_queue_write`, `archer_enet_tx_queue_*`, `archer_enet_host_bind`)
- **Hooks into `hnd.ko`:** `osl_*`, DMA for packet buffers

### Notable Strings (evidence)
- `depends=bcmlibs,bcm_archer_gpl` — module dependency declaration
- `../../bcmdrivers/opensource/net/enet/bcm96756/archer_enet.c` — source path anchor
- `archer_enet_host_bind`, `archer_enet_rx_queue_write` — Archer cross-module hooks
- `dump_sf2_fc_info` — SF2 flow control debug

---

## 4c. bcmvlan.ko — VLAN Filtering (Deep)

**Purpose:** 802.1Q VLAN filtering, VLAN translation, VLAN device creation/teardown, multicast filtering. Source path anchors: `../../bcmdrivers/broadcom/char/vlan/bcm96756/bcm_vlan_dev.c`, `bcm_vlan_local.c`, `bcm_vlan_rule.c`.

**Size:** 137 KB | **Symbols:** 372 defined / 111 undefined | **License:** Proprietary

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **VLAN Core** | `bcmVlan_*` | 77 | `bcmVlan_createVlanDevice`, `bcmVlan_devInit`, `bcmVlan_devHardStartXmit`, `bcmVlan_devIoctl`, `bcmVlan_devGetStats`, `bcmVlan_devChangeMtu`, `bcmVlan_devChangeRxFlags`, `bcmVlan_cleanupVlanDevices`, `bcmVlan_cleanupRuleTables`, `bcmVlan_cleanupTagRules`, `bcmVlan_cleanupRxDefaultActions`, `bcmVlan_blogVlanFlows` |
| **Command Handler** | `cmdHandler_*` | 22 | `cmdHandler`, `cmdHandler_pushVlanTag`, `cmdHandler_popVlanTag`, `cmdHandler_setVid`, `cmdHandler_setCfi`, `cmdHandler_setPbits`, `cmdHandler_setEthertype`, `cmdHandler_setDscp`, `cmdHandler_copyVid`, `cmdHandler_copyCfi`, `cmdHandler_copyPbits`, `cmdHandler_copyTagEthertype`, `cmdHandler_dropFrame`, `cmdHandler_dscp2pbits`, `cmdHandler_ovrdLearningVid` |

### Integration Points
- **Consumes from:** `bcmlibs.ko`, `hnd.ko` (netdevice notifier)
- **Provides to:** `pktflow.ko` (VLAN-tagged flow handling), `bcm_enet.ko` (VLAN-aware ports)
- **Hooks:** `bcm_attach_vlan_hook`, `bcm_detach_vlan_hook`, `bcm_netdev_ext_inherit`, `bcm_vlan_handle_frame_hook`

### Notable Strings (evidence)
- `../../bcmdrivers/broadcom/char/vlan/bcm96756/bcm_vlan_dev.c` — source path anchor
- `[ASSERT] !BCM_VLAN_LL_IS_EMPTY(...)` — VLAN linked-list integrity assertions
- `notifyMcast`, `cMCAST` — multicast notification

---

## 4d. bcm_bpm.ko — Buffer Pool Manager (Deep)

**Purpose:** Packet buffer pool management — allocates/recycles sk_buffs, maintains buffer thresholds, exposes ioctl for monitoring/debug. Runs a monitor thread for pool management.

**Size:** 49 KB | **Symbols:** 211 defined / 45 undefined

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Buffer Pool** | `bpm_*` | 53 | `bpm_drv_open`, `bpm_drv_unlocked_ioctl`, `bpm_buf_expand`, `bpm_calc_num_buf`, `bpm_grow_skb_pool`, `bpm_dump_buffers`, `bpm_dump_skbuffs`, `bpm_dump_status`, `bpm_dump_thresh`, `bpm_pool_manager_exit`, `bpm_monitor_thread` |
| **Ioctl** | `bpmctl_*` | 3 | `bpmctl_ioctl_name`, `bpmctl_op_name`, `bpmctl_subsys_name` |
| **Monitor** | `monitor_*` | 3 | `monitor_task`, `monitor_task_wakeup`, `monitor_task_wqh` |

### Integration Points
- **Consumes from:** `hnd.ko` (`osl_*`, `pktpool_*`), `bcmlibs.ko`
- **Provides to:** `pktflow.ko`, `bcm_enet.ko`, `archer.ko` (packet buffers)

### Notable Strings (evidence)
- `bcm_bpm`, `BPMCTL_IOCTL_MAX`, `bpm_drv_ioctl`, `bpm_get_nvram_value`, `bpmIoctlMutex`
- `name=bcm_bpm`

---

## 4e. bcm_ingqos.ko — Ingress QoS (Deep)

**Purpose:** Ingress QoS — traffic classification, policing, keymask-based flow matching, hardware registration. Exposes ioctl (`iqctl_*`) for control.

**Size:** 41 KB | **Symbols:** 188 defined / 22 undefined | **License:** GPL | **srcversion:** `4D99C947EB822CEB42228F4`

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Ingress QoS** | `iq_*` / `bcm_iq_*` | 25 | `bcm_iq_add_entry`, `bcm_iq_delete_entry`, `bcm_iq_check`, `bcm_iq_check_skb`, `bcm_iq_check_with_mask`, `bcm_iq_check_blog`, `bcm_iq_flush`, `bcm_iq_register_hw`, `bcm_iq_unregister_hw`, `bcm_iq_set_status`, `bcm_iq_add_keymask`, `bcm_iq_delete_keymask`, `bcm_iq_delete_keymask_by_index` |
| **Ioctl** | `iqctl_*` | 3 | `iqctl_ioctl_name`, plus ioctl dispatch |
| **Initialization** | `iqos_*` | 4 | Module init/cleanup |

### Integration Points
- **Consumes from:** `hnd.ko`, `bcmlibs.ko`
- **Provides to:** `archer.ko` (ingress QoS classification), `bcm_enet.ko` (port QoS)

### Notable Strings (evidence)
- `bcm_ingqos`, `bcm_iq_add_entry`, `bcm_iq_check`, `bcm_iq_delete_entry`, `IQCTL_IOCTL_MAX`, `iqctl_ioctl_name`
- `name=bcm_ingqos`

---

## 5. bcm_pcie_hcd.ko + bcm_knvram.ko + bcm_license.ko + bcm_thermal.ko — Platform Drivers

## 5a. bcm_pcie_hcd.ko — PCIe Host Controller Driver (Deep)

**Purpose:** PCIe host controller driver for BCM6756. Manages PCIe link, MSIX/MSI interrupts, BAR mapping, and platform-specific PCIe quirks. Source path anchor: `../../bcmdrivers/opensource/bus/pci/host/bcm96756/pcie_hcd.c`.

**Size:** 110 KB | **Symbols:** 369 defined / 93 undefined | **License:** GPL | **Depends on:** `bcm_knvram`

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **PCIe Core** | `pcie_*` | 48 | `pcie_hcd_*`, `pcie_hcd_msi`, `bcmvpcie_hc_*`, `bcm963xx_hc_msi`, `bcm963xx_hc_is_pcie_link_up` |
| **Platform (963xx)** | `bcm963xx_*` | 22 | `bcm963xx-pcie` probe/remove, `bcm_otp_is_pcie_port_disabled`, `bcm_strap_parse_and_test` |
| **vPCIE** | `bcmvpcie_*` | 11 | `bcmvpcie_hc_access_valid`, virtual PCIe host controller ops |

### Module Parameters (evidence)
`pcie_ssc_cfg`, `pcie_pllclkid`, `pcie_pllclkadj`, `pcie_log_level`, `pcie_boot_order`, `pcie_speed_cfg`, `pcie_apon`, `pcie_phy_pwrmode`, `pcie_errlog`, `pcie_msi`, `pcie_numlanes`, `pcie_acc`, `pcie_linkupretries` — 13 tunable parameters

### Device Tree Aliases (evidence)
`of:N*Tcpci*Cbrcm,bcm-pcie*`, `of:N*Tpci*Cbrcm,bcm947xx-pcie*`, `of:N*Tpci*Cbrcm,bcm963xx-pcie*`, `of:N*Tvpci*Cbrcm,bcm963xx-vpcie*`

---

## 5b. bcm_knvram.ko — Kernel NVRAM (Deep)

**Purpose:** Kernel NVRAM access layer. Exposes `nvram_k_get/set` and `wlcsm_nvram_*` (wireless control service message NVRAM) for reading/writing NVRAM tuples. Used by `hnd.ko` `nvram_*` and `wl.ko` for configuration retrieval.

**Size:** 14 KB | **Symbols:** 55 defined / 30 undefined | **License:** GPL

### Key Exports
- `nvram_k_get`, `nvram_k_set` — kernel NVRAM get/set
- `wlcsm_nvram_get`, `wlcsm_nvram_getall`, `wlcsm_nvram_k_get/set` — WLCSM NVRAM interface
- `_wlcsm_nvram_tuple_insert`, `_wlcsm_nvram_tuple_del`, `_valuepair_set` — internal tuple management

### Integration Points
- **Consumed by:** `hnd.ko` (`si_nvram_*`, `nvram_*`), `wl.ko` (NVRAM-backed config), `dhd.ko` (nvram_path param)
- **Hooks into `hnd.ko`:** `osl_*` for NVRAM spinlock (`nvram_spinlock`)

### Notable Strings (evidence)
- `nvram:%s did not set correctly due to no mem`, `nvram_spinlock`
- `name=bcm_knvram`, `license=GPL`

---

## 5c. bcm_license.ko — License Manager (Deep)

**Purpose:** Broadcom license driver — feature enablement, license parsing, validation, and capability gating. Parses license buffers between `END LICENSE` / `END BCM_LICENSE_FILE` markers.

**Size:** 27 KB | **Symbols:** 102 defined / 38 undefined | **License:** Proprietary | **srcversion:** null

### Key Exports
- `bcm_license_init`, `bcm_license_exit`, `bcm_license_log` — module lifecycle + logging
- `g_licenses` — global license list

### Integration Points
- **Consumed by:** `wl.ko`, `dhd.ko` (feature gating), `archer.ko` (NP feature licensing)
- **Provides license checks** to modules that need licensed features

### Notable Strings (evidence)
- `[ERROR] BCM %s license not valid`, `[ERROR] Failed to parse license`, `[ERROR] Legacy licenses are no longer supported`
- `[NTC] BCM %s license was added`, `[INF] Broadcom License init/exit`, `Licenses cleared`
- `END BCM_LICENSE_FILE`, `END LICENSE`, `driver/license`

---

## 5d. bcm_thermal.ko — Thermal Management (Deep)

**Purpose:** Broadcom thermal driver — temperature monitoring, thermal trip points (temp/hyst/type), CPU freq cooling ops, thermal zone registration. Implements Linux thermal framework integration.

**Size:** 13 KB | **Symbols:** 65 defined / 30 undefined | **License:** GPL

### Key Exports
- `broadcomThermalDriver_init/exit` — module lifecycle
- `broadcomTempDrv_get_trip_temp/hyst/type`, `broadcomTempDrv_set_trip_temp` — trip point management
- `broadcomThermalDrv`, `broadcomTempDrv` — thermal driver structures
- `broadcomCpuFreqCoolingOps`, `broadcomCpuCoolingOps`, `broadcomRebootCoolingOps` — cooling device ops
- `thermalOps` — thermal operations

### Integration Points
- **Consumes from:** Linux thermal framework (`thermal_cooling_device_register/unregister`, `thermal_zone_bind_cooling_device`)
- **Provides thermal zone** to platform / `wl.ko`/`dhd.ko` for temperature-aware transmit power

### Notable Strings (evidence)
- `Failed to register thermal zone device %ld`, `name=bcm_thermal`, `license=GPL`
- `bcm_cpufreq_set_freq_max`, `bcm_io_block_address`

---

## 6. bcmlibs.ko + wlshared.ko + emf.ko + igs.ko + nat46.ko + ripdrv.ko — Support Libraries

## 6a. bcmlibs.ko — Core Broadcom Library (Deep)

**Purpose:** Core Broadcom library of utilities — bitmaps, packet queues/lists, d3lut (destination LUT), string/math/crypto helpers, IP checksum, CRC, bit ops. Foundation utility library used by nearly all modules.

**Size:** 45 KB | **Symbols:** 279 defined / 15 undefined | **License:** GPL | **srcversion:** `353E385987996B610A6E5C2`

### Subsystems

| Subsystem | Symbol Prefix | Count | Key Functions |
|-----------|---------------|-------|---------------|
| **Bitmap** | `bcm_bitmap_*`, `_bcm_bitmap_*` | 36 | `bcm_bitmap_alloc_bitmap`, `bcm_bitmap_pool_alloc/free_bitmap`, `bcm_bitmap_get/set/clear_bit`, `bcm_bitmap_find_next_one/zero`, `bcm_bitmap_pool_dump/copy_bitmap` |
| **d3lut** | `d3lut_*` | 18 | Destination LUT (L2 forwarding table) — `d3lut_*` exported context |
| **Pkt Queue / List** | `pktqueue_*`, `pktlist_*` | ~11 | `pktqueue_context`, `pktlist_context` — packet queue/list management |
| **Utility** | `bcm_*` | 27 | String, math, crypto, TLV, IP checksum, CRC, bit ops |
| **Module** | `init`, `cleanup`, `_bit_pool_*` | — | Bit pool allocation, module entry/exit |

### Integration Points
- **Consumed by:** ALL modules (`bcm_enet`, `pktflow`, `archer`, `bcmvlan`, `bcm_bpm`, `bcm_ingqos`, `wl.ko`, `dhd.ko`, `hnd.ko`)
- **Hooks into `hnd.ko`:** `osl_*` for memory allocation

### Notable Strings (evidence)
- `bcm_bitmap_clear_bit`, `bcm_bitmap_dump`, `bcm_bitmap_find_next_one/zero`, `bcm_bitmap_pool_alloc_bitmap`

---

## 6b. wlshared.ko — WL/DHD Shared Glue (Deep)

**Purpose:** WLAN shared module between system BSP and WLAN driver. Provides common structures/hooks shared between `wl.ko` and `dhd.ko` — bridge FDB updates, d3lut handling, packet coalescing hooks.

**Size:** 8.8 KB | **Symbols:** 51 defined / 10 undefined | **License:** GPL and additional rights

### Key Exports
- `wl_*`: `wl_swdev`, `wl_update_d3lut_and_blog`, `wl_pktc_req/del`, `wl_handle_br`, `wl_br_nf`, `wlshared_module`
- `dhd_*`: `dhd_swdev`, `dhd_handle_br_d3lut`, `dhd_pktc_del/req_hook`, `dhd_swdev_event/notifier`, `dhd_update_d3lut`
- `fdb_*`: `fdb_check_expired_dhd/wl_hook`

### Integration Points
- **Consumed by:** `wl.ko` (depends: `wlshared`), `dhd.ko` (depends: `wlshared`)
- **Provides shared bridge/FDB/d3lut hooks** so wl and dhd stay consistent with the Linux bridge

### Notable Strings (evidence)
- `bcm_br_handle_wl_d3lut`, `bcm_br_wl_query/update_bridgefdb`, `dhd_handle_br_d3lut`, `dhd_pktc_del/req_hook`, `fdb_check_expired_dhd/wl_hook`

---

## 6c. emf.ko — Ethernet Multicast Forwarding (Deep)

**Purpose:** Ethernet Multicast Forwarding — IGMP/MLD snooping, multicast filter database (MFDB) management, multicast control filtering. Registers an IGMP snooper with the multicast subsystem.

**Size:** 25 KB | **Symbols:** 125 defined / 21 undefined | **License:** Dual MIT/GPL | **Depends on:** `hnd`, `bcmmcast`

### Key Exports
- `emfc_*`: `emfc_init`, `emfc_exit`, `emfc_input`, `emfc_ipv6_input`, `emfc_cfg_request_process`, `emfc_iflist_add`, `emfc_mfdb_clear/group_find/ipv6_lookup`, `emfc_igmp_snooper_register/unregister`, `emfc_rtport_add/del`, `emfc_wmf_get_igsc`, `emfc_wmf_scbfind`
- `bcm_mcast_control_filter`, `bcm_mcast_is_snooping_enabled`

### Integration Points
- **Consumed by:** `igs.ko` (depends: `emf`), calls `emfc_igmp_snooper_register/unregister`, `emfc_mfdb_*`, `emfc_rtport_*`
- **Hooks into `hnd.ko`:** `osl_*`, timer

### Notable Strings (evidence)
- `depends=hnd,bcmmcast`, `emfc_init: wrapper parameter NULL`, `cUnknown return value from IGMP Snooper`
- `cIGMP Query send failed`, `cIGMP Snooper couldn't register with EMF`

---

## 6d. igs.ko — IGMP Snooping (Deep)

**Purpose:** IGMP Snooping — multicast group management, IGMPv2/v3 report/leave processing, IGMP query handling. Works with EMF for multicast forwarding.

**Size:** 33 KB | **Symbols:** 124 defined / 54 undefined | **License:** Dual MIT/GPL | **Depends on:** `emf`, `hnd`, `bcmmcast`

### Key Exports
- `igs_*`: `igs_instance`, `igs_proc_stats_get`, `igs_osl_timer`
- `igsc_*`: `igsc_sdb`, `igsc_rtlist`, `igsc_input` (IGMP input processing), IGMPv2 leave/new membership report handling
- `bcm_mcast_notify_register/unregister`

### Integration Points
- **Consumed by:** `wl.ko` (depends: `igs`), `dhd.ko` (depends: `igs`) — wireless multicast snooping
- **Consumes from:** `emf.ko` (`emfc_igmp_snooper_register/unregister`, `emfc_mfdb_*`, `emfc_rtport_*`)
- **Procfs:** `IgmpNotHandled`, `McastGroups`, `McastMembers`, `MemTimeouts`, `ReportTimeouts` stats

### Notable Strings (evidence)
- `depends=emf,hnd,bcmmcast`, `cIGMPV3 type=%x`, `cigsc_input: IGMPv2 leave group received`
- `cOut of memory allocating IGMP Query packet`

---

## 6e. nat46.ko — NAT46 Stateless Translation (Deep)

**Purpose:** NAT46 — stateless IPv4/IPv6 translation. Network device-based translation with rule management, checksum handling, fragment ID rewrite, and procfs interface.

**Size:** 44 KB | **Symbols:** 166 defined / 59 undefined | **License:** GPL

### Key Exports
- `nat46_*`: `nat46_configure`, `alloc_nat46_instance`, `get_nat46_instance`, `is_valid_nat46`, `create/remove_nat46_proc_entry`
- `nat46_netdev` — network device translation
- `mapfrag`, `pairs_xlate_v6_to_v4`, `xlate_v4_to`, `xlate_v6_to` — translation helpers
- `zero_csum`, `frag_id_rewrite`, `csum` — checksum/fragment options

### Module Parameters (evidence)
`debug`, `zero_csum_pass`, `frag_id_rewrite`

### Integration Points
- **Consumed by:** Router/NAT layer (depends: `nf_defrag_ipv6`)
- **Independent** of Wi-Fi stack — used by the CPE's NAT function

### Notable Strings (evidence)
- `nat46: adding device (%s)`, `nat46: configure device (%s)`, `[nat46] Could not copy v4/v6 skb`, `[nat46] Could not find a translation pair v4->v6/v6->v4`
- `description=NAT46 stateless translation`, `name=nat46`, `license=GPL`

---

## 6f. ripdrv.ko — RIP Record Driver (Deep)

**Purpose:** RIP Record Driver — accesses `/proc/rip` for board/certificate information. Implements crypto (AES, RSA, SHA256) for reading/verifying signed RIP records (board info, crypto keys). Uses tomcrypt/tommath.

**Size:** 48 KB | **Symbols:** 181 defined / 65 undefined | **License:** GPL | **Depends on:** `tomcrypt`, `tommath`, `platform`

### Key Exports
- `rip_*`: `rip_proc`, `rip_seq`, `rip_drv_get_flags`, `rip_drv_lock_item`, `rip_cert_privkey_seq_*`, `rip_crypto_decrypt/encrypt`, `rip_bl_crypto_confidkey/integrkey`
- `rip2_*`: `rip2_get`, `rip2_flash`, `rip2` — secondary RIP interface
- `EFU` (Encrypted Firmware Update): `rip_efu_*`, `rip_efu_get_tag`, `rip_efu_get_blonly_tag`, `rip_efu_allowed_proc_*`, `rip_efu_temporal_tag_proc`
- `proc_*`: `proc_create_data`, `proc_mkdir`, `proc_set_size`, `remove_proc_entry`

### Integration Points
- **Consumed by:** Platform/firmware update logic (board info, signed records)
- **Depends on:** `tomcrypt`, `tommath` (crypto), `platform`
- **Procfs:** exposes `/proc/rip` entries

### Notable Strings (evidence)
- `cache_rip_data`, `rip_cert_privkey_seq`, `rip_crypto_decrypt/encrypt`, `rip_efu_get_tag`, `rip_bl_crypto_confidkey/integrkey`
- `sha256`, `aes`, `rsa` — crypto algorithms used

---

## 6g. bcm_archer_gpl.ko — GPL Archer NP Wrapper (Deep)

**Purpose:** GPL-licensed shim exposing the Archer NP to the Linux netdevice stack. Registers a netdevice, binds to Ethernet, manages coherent memory, handles DSL init and CPU affinity.

**Size:** 19 KB | **Symbols:** 107 defined / 44 undefined | **License:** GPL | **srcversion:** `C966FF7CD2BCD65D39F7AD2`

### Key Exports
- `archer_gpl_enet_bind`, `archer_gpl_enet_config` — Ethernet binding
- `archer_coherent_mem_alloc/free` — coherent DMA memory
- `archer_construct/destruct`, `archer_create_netdevice`, `archer_dev_open/start_xmit/change_mtu` — netdevice ops
- `archer_gpl_dsl_init`, `archer_gpl_cpu_affinity_set`, `archer_gpl_irq_type_name_g`
- `archer_host_bind`

### Integration Points
- **Consumed by:** `archer.ko` (depends: `bcm_archer_gpl`), `bcm_enet.ko` (depends: `bcm_archer_gpl`)
- **Consumes from:** `archer.ko` (Archer NP core)

### Notable Strings (evidence)
- `[ASSERT] hooks_p->archer_task_p`, `[ERROR] Could not archer_gpl_dsl_init/sysport_init`, `[ERROR] Could not archer_host_bind`
- `archer_coherent_mem_alloc/free`, `archer_construct/destruct`, `archer_dev_change_mtu/open/start_xmit`

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
├── bcm_pcie_hcd.ko ← bcm_knvram.ko
├── bcm_knvram.ko
├── bcm_license.ko
├── bcm_thermal.ko
├── bcmlibs.ko
├── wlshared.ko
├── emf.ko ← bcmmcast.ko
├── igs.ko ← emf.ko, bcmmcast.ko
├── nat46.ko ← nf_defrag_ipv6
├── ripdrv.ko ← tomcrypt, tommath, platform
└── bcmmcast.ko (referenced)
```

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