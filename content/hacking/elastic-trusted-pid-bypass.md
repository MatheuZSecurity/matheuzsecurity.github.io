---
title: "Singularity Rootkit: Evading Elastic Defend Module Load Detection"
date: 2026-08-31T00:00:00-03:00
description: "Elastic Defend 9.5 added taint_flags to the module_load BPF event and a new detection rule on top of it. Here is how Singularity loads clean: source obfuscation for YARA, trusted_pids insertion for the BPF hook, and OBF_OUT=/var/lib/dkms for the .ko creation rule."
categories: [Malware]
tags: [EDR Evasion, eBPF, Elastic, Linux, Red Team, LKM, Rootkit]
author: 0xMatheuZ
draft: false
ShowToc: true
TocOpen: true
UseHugoToc: true
images:
  - "https://i.imgur.com/E7xbfk7.jpeg"
---

![imgur](https://i.imgur.com/60t8gkg.jpeg)

Rootkit Researchers: https://discord.gg/66N5ZQppU7

Singularity Rootkit: https://github.com/MatheuZSecurity/Singularity

---

Elastic Defend has shipped a BPF-based module load event since around 8.14. With 9.5.0, that event gained a `taint_flags` field, and [PR #6588](https://github.com/elastic/detection-rules/pull/6588) added the EQL detection rule that queries it. The older syslog rule from 2023 is still active and fires independently. Between the two, loading an unsigned or out-of-tree module without any evasion generates alerts from both paths.

So there are two problems to deal with: the YARA scan on the `.ko` file, and the BPF hook on module load.

---

## Setup

The test environment is running Elastic Defend 9.5.2 on Ubuntu with kernel 6.8.0-138-generic. The agent is up and the `module_load` BPF program is loaded and attached:

![elastic-agent status and bpftool showing module_load prog and elastic_ebpf_ev maps](/img/elastic/1.png)

Map id 33 is a `hash` map named `elastic_ebpf_ev` with `key_size=4`. That's `elastic_ebpf_events_trusted_pids`, the one we care about.

---

## The rules

**Rule `cc3dab79`: "Kernel Module Loaded with Tainting Flags"** (new in 9.5.0)

```toml
min_stack_version = "9.5.0"
index = ["logs-endpoint.events.process*"]
language = "eql"

process where host.os.type == "linux" and event.type == "start" and
  event.action == "load_module" and
  process.Ext.load_module.taint_flags != null
```

`process.Ext.load_module.taint_flags` is populated via `BPF_CORE_READ(mod, taints)` inside the `tp_btf/module_load` program. The tracepoint fires after the module's init function returns, so whatever `mod->taints` holds at that point is what gets reported. The field was added in 9.5.0 and is what this rule depends on.

**Rule `05cad2fb`: "Tainted Kernel Module Load"** (2023, still active)

```toml
index = ["logs-system.syslog-*"]
language = "kuery"

host.os.type:linux and data_stream.dataset:"system.syslog" and
  process.name:kernel and
  message:"module verification failed: signature and/or required key missing - tainting kernel"
```

This one depends on filebeat reading `/var/log/syslog` and forwarding it to Elastic. Both rules fire independently of each other.

---

## Two separate problems

The 76 alerts come from two different detection paths that need to be handled independently.

The 69x `Linux.Rootkit.Generic` and 6x `Linux.Rootkit.BrokePKG` alerts are YARA hits on the `.ko` file itself. Elastic scans module files on disk and matches against signatures for known rootkit strings, function names, and patterns. Obfuscating the source with `name_randomizer.py` removes those strings entirely, so YARA has nothing to match on.

The `module_load` BPF event is a separate path. The shipped `elastic-endpoint` binary uses `SEC("tp_btf/module_load")`, confirmed by extracting and disassembling the embedded BPF ELF. That tracepoint fires at the end of `do_init_module()`, after the module's init function has already returned. When it fires, Elastic reads `mod->taints` via `BPF_CORE_READ` and emits a `process.Ext.load_module` event with the module's metadata and taint flags. Rule `cc3dab79` matches when `taint_flags != null`.

Obfuscation handles YARA. The trusted_pids bypass handles the `module_load` event. With the loader's TGID in the map, the BPF program exits before collecting any data, so no event gets emitted and rule `cc3dab79` never gets a chance to match.

---

## Without evasion

Just loading Singularity as-is, no evasion:

![make compiling Singularity from /dev/shm/Singularity](/img/elastic/3.5.png)

![Kibana showing 76 alerts: 69x Linux.Rootkit.Generic, 6x Linux.Rootkit.BrokePKG, 1x Kernel Object File Creation](/img/elastic/3.png)

76 alerts total. YARA catches the `.ko` on disk before it's even loaded. The BPF hook fires after the module finishes initializing, when `tp_btf/module_load` triggers at the end of `do_init_module()`.

---

## Obfuscating the source

`name_randomizer.py` in `obfuscator/` takes care of YARA at the source level. It randomizes function names, renames every `.c` and `.h` file, escapes sensitive strings in `.rodata`, and spits out a new Makefile with only the generated names.

```bash
make obfuscate OBF_OUT=/root/deploy
```

It starts by scanning the source tree and counting how many hookable functions each file exports:

![make obfuscate running: module name fs_util_1hj, scanning modules/ with function counts per file](/img/elastic/4.png)

Then it applies the renames across every file:

![file renaming output: trace.c -> sys_cf941g.c, hooks_write.c -> drv_tuzd0g.c, clear_taint_dmesg.c -> kern_q8s6yd.c, etc.](/img/elastic/4.1.png)

Every source file, every function, every time a different name. The module name itself (`fs_util_1hj` here) is generated fresh on each run too.

`modinfo` after compilation confirms what ships in the `.ko`:

![compilation complete showing fs_util_1hj.ko, modinfo output: license GPL, name fs_util_1hj, vermagic 6.8.0-138-generic](/img/elastic/4.2.png)

No `singularity`, no `hook_`, no `hide_module`, no `kallsyms_lookup_name`. YARA has nothing to match on.

---

## The trusted_pids bypass

Looking at the `module_load` BPF bytecode before it gets to any taint logic:

![bpftool prog dump xlated name module_load showing bpf_get_current_pid_tgid call, map[id:33] lookup (elastic_ebpf_events_trusted_pids), and conditional jump at line 12](/img/elastic/2.png)

Lines 4-12 get the current TGID and look it up in `map[id:33]` (`elastic_ebpf_events_trusted_pids`). The conditional at line 12 checks the lookup result. If the TGID is present in the map, the program exits early and nothing gets emitted.

The loader discovers this map at runtime instead of hardcoding the id. It iterates all loaded BPF programs, finds the one named `module_load` with type `BPF_PROG_TYPE_TRACING`, pulls the full map list via two calls to `BPF_OBJ_GET_INFO_BY_FD`, and takes the first `BPF_MAP_TYPE_HASH` with `key_size == 4`. The map id changes every time the Elastic agent restarts, so hardcoding it would break after the first restart.

```c
uint32_t my_tgid = (uint32_t)getpid();

map_upsert(map_fd, my_tgid);   /* insert BEFORE the syscall */

int ko_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
syscall(__NR_finit_module, ko_fd, "", 0);
close(ko_fd);

map_delete(map_fd, my_tgid);   /* remove immediately after */
```

Running the loader with Elastic Defend 9.5.2 active:

![loader output: found module_load prog fd=3, map id=33 type=1 key=4 name=elastic_ebpf_ev, tgid 3212 -> trusted_pids (bypassed), module loaded. dmesg grep fs_util_ returns empty. dmesg grep taint returns empty.](/img/elastic/5.png)

`tgid 3212 -> trusted_pids (bypassed)`, module loaded. `dmesg | grep fs_util_` comes back empty because the module filters its own name out of the kernel ring buffer using `THIS_MODULE->name`. Same for `dmesg | grep taint`. The module is running and fully hidden.

---

## 0 alerts

![Kibana Alerts page showing 0 alerts, No items found](/img/elastic/6.png)

---

## Bonus: the .ko creation rule

There is a third rule worth knowing about. Rule `1965eab8` fires on `event.type:creation and file.extension:ko`. Any process writing a `.ko` to disk triggers it. It uses `new_terms` on `(process.name, file.name)`: first time that pair appears in 5 days, alert.

```
event.category:file and host.os.type:linux and event.type:creation and file.extension:ko and
not (
  file.path:(/tmp/mkinitramfs* or /var/cache/uptrack/* or /var/tmp/dracut.* or
             /build/* or /var/lib/dkms/* or /var/tmp/portage/* ...)
  or process.executable:("/sbin/dracut" or "/usr/bin/pacman" or /snap/* ...)
  or process.name:"cpio"
)
```

`/var/lib/dkms/*` is in the exclusion list. That's the standard path for out-of-tree driver builds on Debian-based systems, Elastic whitelisted it to avoid noise from normal driver installs. Just point `OBF_OUT` there:

```bash
make obfuscate OBF_OUT=/var/lib/dkms/sg_build
```

The linker writes the `.ko` to `/var/lib/dkms/sg_build/sys_core_nke.ko`. That path matches the exclusion, so the rule never fires.

![make obfuscate OBF_OUT=/var/lib/dkms/sg_build, modinfo showing license GPL name sys_core_nke vermagic 6.8.0-138-generic, loader output tgid 3183 trusted_pids bypassed module loaded, ps aux showing Elastic agent still running](/img/elastic/5.5.png)

`license: GPL`, `name: sys_core_nke`, loads clean. No alerts from the creation rule, no alerts from the load.

---

## What got bypassed

| Detection | How |
|---|---|
| YARA on function names (`hook_`, `hide_module`, `singularity`) | Source obfuscation + rename |
| Rule `cc3dab79` (BPF module load probe, taint_flags field) | trusted_pids insertion before `finit_module` |
| Rule `05cad2fb` (syslog pattern via filebeat) | `read()` hook in `clear_taint_dmesg.c` filters the line |
| Rule `1965eab8` (.ko file creation) | `OBF_OUT=/var/lib/dkms/sg_build` hits the exclusion path |
| `lsmod` / `/proc/modules` / `/sys/module/` | Module list erasure during init |
| `dmesg \| grep <module_name>` | dmesg filter using `THIS_MODULE->name` |

---

## Conclusion

Elastic Defend 9.5.0 made module load detection significantly harder with the `taint_flags` field and the new EQL rule on top of the existing BPF event. The syslog rule has been around since 2023 and is still active. The `.ko` creation rule adds a third layer that catches the file before it ever gets loaded.

None of it matters if the `module_load` event never fires. Inserting the loader's TGID into `elastic_ebpf_events_trusted_pids` before calling `finit_module` causes the BPF program to exit before collecting anything. Combined with source obfuscation to defeat YARA and compiling into `/var/lib/dkms/` to avoid the creation rule, Singularity loads clean with zero alerts.

There are a lot of LKM rootkits out there that get called "sophisticated" and "stealthy" by security companies. Most of them get caught by a YARA signature on disk, hook a handful of syscalls, and call it a day. The marketing does a good job of making that sound more impressive than it is.

Singularity exists to show what EDR-aware actually means in practice.

The loader is not public at the moment.

So that's it, cya hackers!

- 6767676767