---
title: "Trend Micro Deep Security Agent Research: Forcing bmhook/tmhook Reloads to Open a Protection Bypass Window"
date: 2026-06-03T00:00:00-04:00
description: "Security research on a local event-storm condition that makes Trend Micro Deep Security Agent unload and reload bmhook/tmhook, creating a repeatable protection bypass window."
categories: [Linux Kernel, Vulnerability Research]
tags: [Trend Micro, Deep Security Agent, Linux Kernel, LKM, Livepatch, EDR, Bypass, DoS, Vulnerability Research]
author: 0xMatheuZ
draft: false
ShowToc: true
TocOpen: true
UseHugoToc: true
images:
  - "https://i.imgur.com/QPJusUn.png"
---

![architecture](/img/trendmicro-bmhook-tmhook-bypass/architecture.svg)

> **Research scope:** This is security research on Trend Micro Deep Security Agent on Linux.
>
> The finding is not remote code execution and it is not a persistent kill switch. It is a forced security-control gap. A local unprivileged event storm can make the agent unload and reload its own behavior-monitoring kernel modules. During that window, protection behavior changes, and an artifact that was normally blocked was written to disk successfully.

![Trend Micro bmhook/tmhook reload bypass demo](https://i.imgur.com/awlvKGo.gif)

## Introduction

This research started from an attacker question, not a defensive tuning question:

```text
Can a local unprivileged process create enough pressure on an endpoint security sensor to make the product remove its own kernel monitoring path?
```

The first C proof of concept was intentionally noisy. It generated a large volume of filesystem and process events. At first, the result looked like normal resource pressure. The kernel reported fork pressure, `perf` lowered its sample rate, and the Trend Micro modules continued to recover.

In this article, I use `event storm` to mean a sustained burst of ordinary local activity that creates many security-relevant events in a short period of time. In this case, the activity was file writes, truncates, renames, symlink operations, forks, and process exits. None of those operations are special by themselves. The interesting behavior appeared when they were generated at high volume against a host running the Trend Micro agent.

Then something more interesting appeared in `dmesg`:

```text
livepatch: 'tmhook': starting unpatching transition
livepatch: signaling remaining tasks
livepatch: 'tmhook': unpatching complete
tmhook: tmhook 1.2.2129 unloaded
tmhook: breadcrumb file created...
livepatch: enabling patch 'tmhook'
livepatch: 'tmhook': starting patching transition
tmhook: tmhook 1.2.2129 loaded
tmhook: breadcrumb file removed...
livepatch: 'tmhook': patching complete
```

At that point I had a question: did the kernel module crash, or did something deliberately unload it?

The answer was not a crash. The agent itself was running `rmmod`.

The finding can be summarized as:

```text
A local unprivileged filesystem/process event storm can trigger Trend Micro Deep Security Agent to run rmmod against bmhook and tmhook. This creates a repeatable temporary window where behavior monitoring is absent or degraded. During that window, content that was normally blocked by Trend Micro was written to disk successfully.
```

That last sentence is the important part. A temporary reload is not automatically a vulnerability. The offensive angle appears when a local unprivileged user can intentionally trigger that recovery path and use the resulting gap to perform actions that the product normally blocks.

In a real intrusion chain, a local foothold is already enough for an attacker to stage tools, drop malware, unpack payloads, or execute post-exploitation components. If the endpoint protection can be pushed into a short blind spot on demand, that blind spot becomes useful even if it lasts only a few seconds. The module comes back, but the file, process, or execution event that happened during the gap may already be gone.

![Impact window showing LKM down and a normally blocked artifact landing on disk](/img/trendmicro-bmhook-tmhook-bypass/impact-window.png)

The screenshot above shows the practical shape of the issue. The PoC detects `LKM DOWN`, `bmhook` disappears first, `tmhook` later enters its livepatch reload cycle, and a separate terminal captures an artifact landing on disk during the same window. I am using a sanitized description in the article because the important point is the protection decision, not the public distribution of a specific payload command.

## TL;DR

The short version:

```text
1. Trend Micro Deep Security Agent loads tmhook as a livepatch syscall hook.
2. bmhook depends on tmhook and implements behavior monitoring.
3. A local event storm stresses file, rename, symlink, truncate, fork, and exit paths.
4. The agent process ds_am.init responds by running rmmod bmhook and rmmod tmhook.
5. tmhook enters livepatch unpatch and patch transitions.
6. The unload is temporary, but the trigger is repeatable.
7. During the reload window, a normally blocked artifact download was allowed and remained on disk.
8. In one observed cycle, the full livepatch transition lasted about 19.6 seconds, with `tmhook` absent for about 1.3 seconds.
```

Confirmed impact:

```text
Local, temporary, repeatable protection bypass.
```

Not proven:

```text
Permanent unload without automatic reload
Privilege escalation
Kernel code execution
Remote exploitation
Kernel panic
```

My current severity assessment is **High**, because the condition is local but it affects a security control directly and the bypass window was observable in practice.

## Research Questions

I tried to keep the investigation grounded around a few concrete questions:

```text
1. Is the module actually unloading, or is dmesg only showing a livepatch state transition?
2. If it unloads, is it caused by a crash or by a userspace process?
3. Which process is responsible for the unload?
4. Is the reload temporary or can the module remain unloaded?
5. Does the gap change protection behavior in a measurable way?
6. Is the behavior repeatable under local unprivileged conditions?
```

The answers I reached were:

```text
1. The module unload is real.
2. It is not a kernel crash in my reproduction.
3. ds_am.init runs rmmod for bmhook and tmhook.
4. The unload is temporary because the agent reloads the modules.
5. Protection behavior changes during the gap.
6. The gap is repeatable with a local event storm.
```

This is why I am not describing the issue as kernel memory corruption or a persistent agent kill. The evidence points to a forced recovery path in the security product, not a direct corruption primitive.

## Threat Model

The assumed attacker is a local unprivileged user or a process running under a normal user account. This is realistic for many Linux endpoint scenarios:

```text
Compromised developer workstation
Compromised low-privilege service account
Malicious insider account
Initial malware running without root
Post-exploitation tool dropped by another vulnerability
```

The attacker does not need to load a kernel module, write to `/lib/systemd/system`, disable the service, or call `rmmod` directly. The key behavior is that the Trend Micro agent itself performs the privileged unload and reload.

The security property under test is not root access. The security property under test is endpoint protection continuity:

```text
Can an unprivileged local workload cause the security agent to temporarily remove its own behavior monitoring hooks?
```

In my lab, the answer was yes.

## Environment

The tests were performed in a local Ubuntu lab environment running Trend Micro Deep Security Agent. The relevant module versions observed during the research were:

```text
tmhook
  version: 1.2.2129 Commit 1.8643.a398302
  description: Trend Micro Generic Syscall-Hooking Module 1.2.2129
  livepatch: Y
  signer: Trend Micro Deep Security 2022

bmhook
  version: 1.2.2120.2129 Build 1.2.2129 Commit 1.8643.a398302
  description: Trend Micro Behavior Monitoring Module 1.2.2120.2129
  depends: tmhook

dsa_filter
  version: 12.6.0.7683
  description: DSA Filter Driver
  depends: dsa_filter_hook

dsa_filter_hook
  version: 1.0
  description: A universal netfilter hook frontend
```

The behavior discussed in this post centers on `tmhook` and `bmhook`. The `dsa_filter` modules are part of the network filtering stack and were not the primary target of the event storm.

The file hashes from the modules I inspected were:

```text
tmhook
  2783a58ba04b27e50db85b7d0ea3055f856265b0e3da03e0be90adbac6e462fa

bmhook
  4706ed090b5360f2da011b283df27d790e72d30d23706400e8b9799b61858d45

dsa_filter
  2c86f826f7d84284d873432bc115577deaa6fd3b19dac4e2cf9c474a68835f08

dsa_filter_hook
  679a3ecfc9051fccccf44bff8d94fdba3e6d1a67d1aadeb77739228925e79de8
```

The systemd context is covered later in the article because it matters for attribution. The short version is that systemd was not responsible for restarting the service during my tests. The module reload behavior came from inside the Trend Micro agent stack.

## Why tmhook and bmhook Matter

The module metadata already tells part of the story:

```text
tmhook: Generic Syscall-Hooking Module
bmhook: Behavior Monitoring Module
```

`tmhook` is a livepatch-based syscall hook layer. It hooks the syscall dispatch path and provides registration APIs that other Trend Micro components can use. `bmhook` depends on it and implements the behavior monitoring pipeline.

From module symbols and strings, the relationship looks like this:

```text
tmhook
  tmhook_register_hook
  tmhook_unregister_hook
  tmhook_handler
  tmhook_prehandler
  tmhook_get_real_fn
  klp_enable_patch
  livepatch_native_sys_call
  livepatch_compat_sys_call

bmhook
  bmhook_scan_enqueue
  bmhook_get_queue_event
  bmhook_throttle_check
  tmbpf_send_event
  bmhook_self_protection_fork
  bmhook_self_protection_exit
  process_exit_post_handler
  async_event_queue
  per_cpu_event_queue
```

That gave me a good mental model:

```text
local syscall
    -> tmhook livepatch dispatcher
    -> bmhook prehook/posthook logic
    -> behavior event object
    -> queue or scanner path
    -> userspace agent
```

The original PoC did not need to target a single exotic syscall. It only needed to generate enough normal activity across paths that behavior monitoring cares about.

The important distinction is:

```text
tmhook is the generic syscall hook layer.
bmhook is the behavior monitoring layer built on top of it.
```

So the earliest observable protection gap is often `bmhook` disappearing first. `tmhook` may still be loaded at that moment, but the behavior monitoring layer is already being removed.

That is exactly what the cleaned-up PoC observed:

```text
bmhook=0 tmhook=1
```

From a security perspective, this state is already interesting. The low-level hook substrate may still exist, but the behavior monitoring consumer has been unloaded.

## The Original Trigger

The first PoC was intentionally heavy. It generated several classes of events at the same time:

```text
open/write/close/truncate
rename
symlink/open/unlink
fork/exit
```

The PoC was not sophisticated. It was basically a local event storm. The important part was that the event types lined up with behavior monitoring:

```text
File content changed
File size changed
File renamed
Symlink created and removed
Child process created and exited
```

After the storm ran for a while, the kernel logs showed pressure:

```text
cgroup: fork rejected by pids controller
perf: interrupt took too long, lowering kernel.perf_event_max_sample_rate
```

Those messages alone do not prove a vulnerability. They only prove the host was under pressure.

The important evidence came later, when the modules started to unload and reload.

The early version was not elegant, and that was intentional. I wanted broad coverage across event classes before narrowing the trigger. Once the module reload behavior was confirmed, I replaced the first noisy version with a cleaner research harness that keeps the same pressure profile but adds module-state monitoring and timestamped evidence.

## Methodology

The investigation had three phases.

First, I ran the original storm and watched the kernel:

```text
dmesg
journalctl -u ds_agent.service
lsmod
/proc/modules
```

That showed the livepatch transitions but did not explain who caused them.

Second, I traced module unloads and process execution. The goal was to distinguish these possibilities:

```text
kernel fault
manual rmmod
systemd restart
Trend Micro internal recovery
```

Third, I tested whether the reload window changed protection behavior. This is the step that turned the finding from "interesting recovery behavior" into a security issue.

The evidence chain looked like this:

```text
event storm begins
    -> cgroup and perf pressure appear
    -> ds_am.init executes rmmod bmhook
    -> kernel frees bmhook
    -> ds_am.init executes rmmod tmhook
    -> tmhook livepatch unpatch begins
    -> tmhook unloaded
    -> tmhook loaded again
    -> patching complete
    -> protection behavior differs during the gap
```

Each stage was independently observable through either kernel logs, bpftrace, service logs, or the PoC output.

## Proving Who Unloaded the Modules

The first key question was whether the kernel module crashed or whether a privileged process unloaded it.

I used `bpftrace` to watch `execve` for `rmmod` and `module_free` events. The result was clear:

```text
EXEC rmmod pid=135640 comm=ds_am.init file=/usr/sbin/rmmod cmdline=rmmod bmhook
FREE module=bmhook by rmmod pid=135640 comm=rmmod

EXEC rmmod pid=136069 comm=ds_am.init file=/usr/sbin/rmmod cmdline=rmmod tmhook
FREE module=tmhook by rmmod pid=136069 comm=rmmod
```

This proved two things:

```text
1. The unload was real.
2. The unload was initiated by Trend Micro's own ds_am.init process.
```

It was not a random kernel crash. It was not my PoC calling `rmmod`. The agent itself initiated recovery by unloading the behavior monitoring modules.

![bpftrace showing ds_am.init executing rmmod for bmhook and tmhook](/img/trendmicro-bmhook-tmhook-bypass/bpftrace-rmmod.png)

I also used a second version of the trace that records fork relationships before `execve`, then prints the parent process metadata when `rmmod` runs. In my reproduction, the important line was:

```text
EXEC rmmod pid=135640 comm=ds_am.init file=/usr/sbin/rmmod cmdline=rmmod bmhook
EXEC rmmod pid=136069 comm=ds_am.init file=/usr/sbin/rmmod cmdline=rmmod tmhook
```

This is the strongest single screenshot in the evidence chain because it removes ambiguity. The userland process that enters `execve` is not the PoC. It is Trend Micro's own `ds_am.init`.

This changed the interpretation completely.

If the kernel had crashed inside `tmhook` or `bmhook`, the finding would have been a kernel stability issue. If my test had required root to run `rmmod`, the finding would have been expected administrative behavior. Neither was true.

The relevant security property is that an unprivileged local workload caused a privileged security agent process to remove its own monitoring modules.

## The Agent Service Context

The systemd unit was also useful:

```ini
[Service]
Type=forking
Restart=no
TimeoutSec=5min
ExecStart=/opt/ds_agent/ds_agent.init start
ExecStop=/opt/ds_agent/ds_agent.init stop
TasksMax=1024
LimitNOFILE=2048
```

`Restart=no` means systemd was not restarting the service. The service remained active. The reload was internal to the Trend Micro agent stack.

The service status showed the relevant processes:

```text
/opt/ds_agent/ds_agent -w /var/opt/ds_agent -b -i -e /opt/ds_agent/ext
/opt/ds_agent/ds_am -g ../diag -v 5 -d /var/opt/ds_agent/am -P 1 -R
/opt/ds_agent/netagent/tm_netagent ...
```

The logs around the reload were also interesting:

```text
ds_am.init: startBM enableBLP=1 thresholdBLP=100
ds_am.init: insmod /opt/ds_agent/6.8.0-85-generic/tmhook.ko enable_loop_prevention=1
ds_am.init: update_bm_cgroup_path ...
ds_am.init: successfully configured cgroup v2
```

The `enable_loop_prevention` parameter is present in the module metadata, and the log includes `enableBLP=1 thresholdBLP=100`. I am treating `BLP` as behavior loop prevention or a closely related recovery mechanism. That part is an inference, but the unload and reload sequence is not an inference. It was captured directly.

That makes the probable design behavior look like this:

```text
bmhook detects or causes excessive behavior-monitoring activity
    -> loop prevention threshold is reached
    -> ds_am.init restarts Behavior Monitoring
    -> bmhook is removed
    -> tmhook is removed
    -> tmhook is inserted and livepatched again
    -> bmhook is restored
```

If this interpretation is correct, the vulnerability is not "the recovery path exists." The vulnerability is that the recovery path removes the exact protection layer that is supposed to observe or block malicious behavior, and the path can be reached by local attacker-controlled activity.

## Reversing Notes

The modules were not stripped, which made symbol-level inspection useful.

I used a lightweight reversing approach. The goal was not to fully decompile the product. The goal was to answer four practical questions:

```text
1. Which module owns syscall hooking?
2. Which module owns behavior monitoring?
3. Which functions suggest queueing, throttling, and recovery?
4. Does the binary structure match the runtime logs?
```

For `tmhook`, `modinfo` showed:

```text
description: Trend Micro Generic Syscall-Hooking Module 1.2.2129
livepatch: Y
parm: do_livepatch:int
parm: tmhook_ptregs_syscall_with_posthook:int
parm: enable_loop_prevention:int
```

Static metadata also showed that `tmhook` is signed by Trend Micro and loaded as a Linux livepatch module:

```text
name:        tmhook
version:     1.2.2129 Commit 1.8643.a398302
description: Trend Micro Generic Syscall-Hooking Module 1.2.2129
livepatch:   Y
signer:      Trend Micro Deep Security 2022
vermagic:    6.8.0-84-generic SMP preempt mod_unload modversions
```

In `tmhook`, the initialization path calls the livepatch setup:

```text
init_module
    -> tmhook_lookup_symbols
    -> tmhook_init_hook
    -> tmhook_arch_init
    -> asm_init_livepatch
    -> klp_enable_patch
```

`asm_init_livepatch` references:

```text
do_livepatch
asm_init_livepatch_sys_call_dispatcher
klp_enable_patch
tmhook_set_config
```

![Binary Ninja view of tmhook livepatch initialization](/img/trendmicro-bmhook-tmhook-bypass/bn-tmhook-livepatch.png)

The `asm_init_livepatch` function is the cleanest static link between `tmhook.ko` and the kernel logs. The function checks `do_livepatch`, calls `asm_init_livepatch_sys_call_dispatcher()`, assigns `funcs_dispatcher`, and then reaches `klp_enable_patch(&patch)`.

That matches the kernel messages:

```text
livepatch: enabling patch 'tmhook'
livepatch: 'tmhook': starting patching transition
tmhook: tmhook 1.2.2129 loaded
```

The exported symbols also tell the story clearly:

```text
tmhook_register_hook
tmhook_unregister_hook
tmhook_rebase_hook
tmhook_get_next_fn
tmhook_get_handler_fn
tmhook_get_real_fn
tmhook_attach_data
tmhook_remove_data
tmhook_find_data
tmhook_detach_data
tmhook_get_nr_syscalls
tmhook_get_systable_fn
```

![Binary Ninja view of tmhook_register_hook calling register_hook](/img/trendmicro-bmhook-tmhook-bypass/bn-tmhook-register-hook.png)

The Binary Ninja view above shows `tmhook_register_hook()` validating the hook metadata and reaching `register_hook()`. This is useful because it visually confirms that `tmhook` is not just a black-box kernel blob in the article. The symbol table and decompiler point to `tmhook` acting as a generic hook registration layer.

Those names are exactly what I would expect from a generic hook substrate. `tmhook` owns the syscall hook dispatching layer. `bmhook` uses it.

For `bmhook`, the initialization path is much larger:

```text
bmhook_mm_init
bmhook_worker_init
bmhook_throttle_init
bmhook_fs_config_init
bmhook_uprobe_init
bmhook_scan_init
bmhook_dev_init
bmhook_proc_init
bmhook_self_protection_init
bmhook_prog_init
```

The module relationship is explicit in `modinfo`:

```text
name:        bmhook
version:     1.2.2120.2129 Build 1.2.2129 Commit 1.8643.a398302
description: Trend Micro Behavior Monitoring Module 1.2.2120.2129
depends:     tmhook
signer:      Trend Micro Deep Security 2022
```

The relationship is also visible in the decompiler. `bmhook_add_hook()` builds a hook descriptor with behavior monitoring callbacks:

![Binary Ninja view of bmhook_add_hook preparing prehook and posthook handlers](/img/trendmicro-bmhook-tmhook-bypass/bn-bmhook-prepost.png)

The important fields are the handler assignments:

```text
bmhook_prehook_handler
bmhook_posthook_handler
bmhook_posthook_cleaner
bmhook_hooks_mutex
```

Shortly after that setup, the same function registers the prepared descriptor through `tmhook_register_hook()`:

![Binary Ninja view of bmhook_add_hook calling tmhook_register_hook](/img/trendmicro-bmhook-tmhook-bypass/bn-bmhook-registers-tmhook.png)

This is the most important static relationship in the reversing notes:

```text
bmhook prepares behavior-monitoring prehook/posthook callbacks
    -> bmhook_add_hook()
    -> tmhook_register_hook()
    -> tmhook hook substrate
```

The queue path was also visible:

```text
bmhook_scan_enqueue
    -> kmem_cache_alloc
    -> enqueue_entry
    -> __wake_up or __wake_up_sync
```

`enqueue_entry` checks whether a monitor PID exists and then links the event into a queue. When the event storm becomes heavy enough, the behavior monitoring stack appears to enter a recovery path that unloads and reloads the hooks.

Another clear event-path function is `bmhook_add_queue_event()`:

![Binary Ninja view of bmhook_add_queue_event and event queue handling](/img/trendmicro-bmhook-tmhook-bypass/bn-bmhook-queue-event.png)

That function selects between `bm_event_queue_async`, `bm_event_queue`, and `bm_event_queue_per_cpu`, checks `bmhook_get_monitor_pid_read_once()`, links work into `bm_pending_queue_event_list`, and wakes `bm_queue_monitor_wq`. This is the behavior-monitoring pipeline that the event storm is pressuring.

The `bmhook` symbol set also contains several names that line up with a behavior monitoring engine:

```text
tmbpf_send_event
tmbpf_send_event_async
tmbpf_send_event_sync
tmbpf_get_file_info_from_path
tmbpf_get_file_info_from_fd
tmbpf_get_process_comm
tmbpf_get_task_exit_status
bmhook_event_config_write
bmhook_fs_config_write
bmhook_throttle_check
bmhook_self_protection_fork
bmhook_self_protection_exit
```

The strings were even more useful because they expose internal feature names and failure paths:

```text
enable_loop_prevention
bmhook_migrate_queue
bmhook_scan_init
bmhook_get_queue_event
bmhook_set_monitor_queue
bmhook_rem_bpf_throttle
bmhook_add_bpf_throttle
async_event_queue
per_cpu_event_queue
bmhook_throttle_check(%u) - throttled
bmhook_send_event(%u) - throttled
tmbpf_send_event() - bmhook_scan_enqueue(mode=%d) failed
TELEMETRY_EVENT_DROPPED_COUNT
event.dropped
config/enable_loop_prevention
```

Two strings are especially important:

```text
Abnormal module unload behavior detected. pid=%d, comm=%s
bmhook %s unloading
bmhook %s unloaded
```

The same class of string exists in `tmhook`:

```text
Abnormal module unload behavior detected. pid=%d, comm=%s
tmhook %s unloaded
breadcrumb file created
breadcrumb file removed
```

This matters because the binary itself contains logic and messages around abnormal unload behavior. The runtime trace then shows `ds_am.init` performing the unload with `rmmod`. The static and dynamic evidence point to the same subsystem.

These names suggest that bmhook is not just passively observing syscalls. It collects subject and object data, tracks event configuration, applies throttling, and sends events to the monitoring side.

The presence of throttling is not surprising. Endpoint products need throttling to survive real workloads. The problem appears when throttling or loop prevention escalates into unloading monitoring hooks in a way that creates an attacker-controllable bypass window.

I cannot claim source-level root cause from symbol inspection alone. But the symbol names align very closely with the runtime behavior:

```text
event storm
    -> behavior queue pressure
    -> loop-prevention or recovery path
    -> ds_am.init rmmod bmhook
    -> ds_am.init rmmod tmhook
    -> tmhook livepatch unpatch/repatch
```

This is a hypothesis about root cause, not a vendor source-code claim. The hard facts are the unload, reload, responsible process, and protection change during the gap.

## Repeated Reload Windows

This did not happen just once. The same trigger caused repeated livepatch reload cycles.

![timeline](/img/trendmicro-bmhook-tmhook-bypass/timeline.svg)

Example kernel log:

```text
[ 1243.387693] livepatch: 'tmhook': starting unpatching transition
[ 1258.396741] livepatch: signaling remaining tasks
[ 1260.010027] livepatch: 'tmhook': unpatching complete
[ 1261.635623] tmhook: tmhook 1.2.2129 unloaded
[ 1262.918644] tmhook: breadcrumb file created...
[ 1262.938475] livepatch: enabling patch 'tmhook'
[ 1262.950906] livepatch: 'tmhook': starting patching transition
[ 1262.983163] tmhook: tmhook 1.2.2129 loaded
[ 1262.983194] tmhook: breadcrumb file removed...
```

Another cycle followed shortly after:

```text
[ 1277.973929] livepatch: 'tmhook': starting unpatching transition
[ 1293.338868] livepatch: signaling remaining tasks
[ 1294.999011] livepatch: 'tmhook': unpatching complete
[ 1296.188671] tmhook: tmhook 1.2.2129 unloaded
[ 1297.278305] tmhook: breadcrumb file created...
[ 1297.303676] livepatch: 'tmhook': starting patching transition
[ 1297.344095] tmhook: tmhook 1.2.2129 loaded
[ 1313.686336] livepatch: 'tmhook': patching complete
```

This matters because a temporary window is not automatically serious if it is rare and accidental. Here, the window was attacker-triggerable and repeatable.

Approximate timings from one cycle:

```text
unpatch start:       1243.387693
unpatch complete:    1260.010027
tmhook unloaded:     1261.635623
tmhook loaded:       1262.983163
```

That gives several windows to think about:

```text
livepatch transition window: about 19.6 seconds
module absent window: about 1.3 seconds
full recovery until patching complete: longer, depending on task convergence
```

The short module-absent interval is enough to matter if the attacker can wait for it. The longer transition interval may also matter because tasks are being moved across livepatch states and behavior monitoring is in recovery.

## PoC Output

The cleaned-up PoC watches `/proc/modules` while generating the event storm. The first stage of the gap is usually visible when `bmhook` disappears:

```text
./exploit /dev/shm/trend-poc 600 64 512 4 4
[*] dir=/dev/shm/trend-poc seconds=600 workers=64 files/worker=512 forkers=4 symlinkers=4
[*] monitoring /proc/modules for bmhook/tmhook unload
[  75s] events=     5479173 bmhook=1 tmhook=1 window_seen=0
[!] hook reload window detected: bmhook=0 tmhook=1
[+] benign marker actions completed during window
[ 241s] events=    64584240 bmhook=1 tmhook=1 window_seen=1
```

This is important: the monitoring gap can start before `tmhook` is fully unloaded. `bmhook` is the behavior monitoring module. If `bmhook=0`, behavior monitoring is already affected, even while `tmhook` is still present.

## PoC Design

The original PoC was intentionally broad because I did not know which event class would trigger the recovery. It combined:

```text
many worker threads
many files per worker
write and truncate cycles
close and reopen cycles
rename loops
symlink create, open, read, unlink cycles
fork and exit cycles
```

After confirming the bug, I cleaned up the PoC for research purposes. It does three things:

```text
1. Generates high-rate benign filesystem and process events.
2. Monitors bmhook and tmhook through /proc/modules.
3. Creates a benign marker when either module disappears.
```

The high-level logic is:

```text
start module monitor thread
start file event worker threads
start optional fork workers
start optional symlink workers

while running:
    create and write files
    truncate files
    rename files
    create and remove symlinks
    create short-lived child processes
    check whether bmhook or tmhook disappeared
```

I am not publishing the full PoC bypass here. For this research, the important trigger is the event storm, and the important proof is the module reload evidence.

The final trigger parameters that reproduced the gap in my lab were:

```text
duration: 600 seconds
workers: 64
files per worker: 512
fork workers: 4
symlink workers: 4
base directory: tmpfs under /dev/shm
```

Those values are not necessarily minimal. They are the values I used to reproduce the issue consistently after narrowing the event classes.

## Protection Bypass Test

The strongest practical result was not just the reload. It was what happened during the reload window.

In the normal state, Trend Micro blocked a known test artifact download. The file did not remain on disk.

![Baseline behavior where Trend Micro removes the downloaded artifact automatically](/img/trendmicro-bmhook-tmhook-bypass/baseline-auto-removal.png)

This baseline matters. The download reached the host, but the artifact was removed automatically by the product before it remained visible in the target directory. That gave me a clean comparison point for the reload-window test.

During the `bmhook` and `tmhook` reload window, the same category of normally blocked download completed and the file remained present on disk:

```text
-rwxrwxr-x 1 ubuntu ubuntu 18K Jun  3 15:41 test-artifact
Bypass worked
```

The important security finding is that protection behavior changed during the forced module reload window.

If a security product normally blocks a known malicious or unwanted artifact, and the same artifact can be written to disk during a forced monitoring reload, then the issue is no longer just "the module restarted." It is a protection bypass.

The same window could be useful to an attacker for several actions:

```text
writing a malware payload that is normally blocked
unpacking a second-stage tool
renaming or chmoding a payload before scanning catches up
executing a short-lived helper during the monitoring gap
modifying files that would normally trigger behavior telemetry
staging post-exploitation tools in tmpfs
```

The normally blocked artifact being written and left on disk during the gap shows that the protection decision changed.

The impact statement is:

```text
A local unprivileged user can trigger a repeatable module reload window in which behavior monitoring and protection can be bypassed temporarily.
```

![Bypass window where the artifact remains on disk while the LKM is down](/img/trendmicro-bmhook-tmhook-bypass/impact-window.png)

## Why a Temporary Gap Still Matters

It is tempting to dismiss a temporary unload because the modules come back. I do not think that is the right model.

Endpoint security is often about catching the first few seconds of behavior:

```text
download
write to disk
chmod
rename
execute
delete
inject
connect
```

If the monitoring layer disappears during those actions, the later recovery of the hook does not necessarily reconstruct what happened. Some events are instantaneous. Some files can be moved, replaced, or removed. Some processes can execute and exit before the product is fully active again.

The window also does not need to be permanent if it is repeatable. An attacker can wait for or trigger repeated gaps and perform one small action per gap. That turns a short blind spot into a practical sequence of missed events.

This is the main reason I consider the issue security-relevant even though the agent recovers.

## Why This Is a Vulnerability

One possible vendor response is: "This is expected loop prevention."

That may be true internally, but it does not make the behavior safe.

The issue is not that the agent has a recovery mechanism. Recovery mechanisms are normal. The issue is that a local unprivileged user can trigger that recovery mechanism on demand and create a monitoring gap.

The security boundary being affected is the behavior monitoring feature itself.

I would classify the bug as:

```text
CWE-693: Protection Mechanism Failure
CWE-400: Uncontrolled Resource Consumption
CWE-770: Allocation of Resources Without Limits or Throttling
```

My practical classification:

```text
Local temporary protection bypass via forced behavior-monitoring module reload.
```

Severity:

```text
High, if the bypass of blocked content is reproducible in the vendor environment.
Medium to High, if only the forced reload is accepted but bypass impact is not reproduced.
```

I would not call it Critical based on the current evidence because:

```text
It is local.
The unload is temporary.
I did not prove privilege escalation.
I did not prove arbitrary kernel code execution.
I did not prove remote triggering.
```

But I also would not dismiss it as a simple DoS. A security product unloading its own syscall and behavior monitoring modules under attacker-controlled local pressure is a meaningful protection failure.

## What Is Temporary and What Is Repeatable

The unload is temporary:

```text
tmhook unloaded
tmhook loaded
patching complete
```

The condition is repeatable:

```text
unpatching transition
unloaded
loaded
patching complete
unpatching transition
unloaded
loaded
patching complete
```

That distinction matters.

If the vendor asks whether the bypass is permanent, the answer is no. The agent reloads the modules automatically in my reproduction.

If the vendor asks whether the gap is attacker-triggerable, the answer is yes. The event storm caused repeated unload and reload cycles.

## Evidence to Capture During Reproduction

Useful evidence:

```text
dmesg
  livepatch unpatching transition
  tmhook unloaded
  tmhook loaded
  patching complete

bpftrace
  ds_am.init executing rmmod bmhook
  ds_am.init executing rmmod tmhook
  module_free for bmhook and tmhook

agent logs
  startBM
  enableBLP
  insmod tmhook.ko enable_loop_prevention=1
  cgroup path reconfiguration

PoC output
  bmhook=0 or tmhook=0
  window_seen=1

protection evidence
  normal blocked behavior
  changed behavior during reload window
```

The reproduction is easiest to understand when these four pieces of evidence are captured separately:

```text
1. Terminal with bpftrace showing ds_am.init running rmmod.
2. dmesg showing tmhook unpatch, unload, reload, and patch complete.
3. PoC output showing bmhook=0 or tmhook=0.
4. Product UI or logs showing normal blocking compared with the gap behavior.
```

The two screenshots above are the core impact comparison:

```text
Normal state:
  the artifact is removed automatically.

Reload window:
  the artifact remains on disk after bmhook/tmhook protection drops.
```

## Disclosure Timeline

I first reported this class of issue to Trend Micro as a kernel module denial-of-service caused by filesystem event flooding. At that time, the observation was mostly framed around module instability and reload behavior. Later testing made the security impact clearer because the reload window could be correlated with a protection bypass.

The important context is that I did not publish immediately after the first report. I sent the PoC, a reproduction video, diagnostics, and multiple follow-ups. After months without a final triage result, fix timeline, CVE decision, or conclusive answer from the vendor, I decided to publish the research.

Timeline:

```text
2026-02-06
  Initial report sent to Trend Micro.
  Subject: Kernel Module DoS via Filesystem Event Flooding.
  Summary: local unprivileged event storm can trigger unload/reload behavior in Trend Micro Linux kernel modules.

2026-02-25
  Follow-up sent asking for status.

2026-02-26
  Trend Micro acknowledged the report.

2026-02-26
  PoC code and a reproduction video were provided to Trend Micro.

2026-03-09
  Follow-up sent asking for updates.

2026-03-18
  Trend Micro replied that ds_am has its own OOM mechanism and suspected that ds_am OOM might be triggered.
  Trend Micro requested a diagnostic package.

2026-03-18
  Diagnostic packages were provided.
  One package was collected while the PoC was running.
  Another package was collected after the PoC finished and the kernel module had already unloaded.

2026-03-20
  Trend Micro confirmed that the diagnostic packages were forwarded to their backend team.

2026-04-02
  Follow-up sent asking for vulnerability status.

2026-04-09
  Trend Micro replied that the backend team was still processing and reviewing the logs.

2026-04-14
  Follow-up sent offering additional information.

2026-05-04
  Follow-up sent asking whether the issue had been reproduced or triaged internally and whether there was an estimated timeline.

2026-05-31
  Follow-up sent asking for updates.
  No conclusive vendor response had been received by the time of publication.

2026-06-03
  Additional local testing confirmed that ds_am.init runs rmmod against bmhook and tmhook and that a normally blocked artifact can land on disk during the reload window.
  I decided to publish after the long response gap and after confirming the issue as a protection bypass rather than only a module reload or DoS.
```

I am publishing this as security research because the issue is local, temporary, and not a full host compromise by itself, but the protection gap is real and repeatable. The goal is to document the behavior and evidence clearly after a prolonged vendor response gap.

The most important correction to my original report is this:

```text
The issue is not only a kernel module DoS.
It is a local protection bypass caused by a forced behavior-monitoring reload path.
```

## Conclusion

This finding is not a kernel memory corruption bug, and it is not a persistent kill switch for the Trend Micro agent.

It is still a real security issue, because the component that disappears is the component responsible for behavior monitoring.

A local unprivileged event storm can force Trend Micro Deep Security Agent into a behavior monitoring recovery cycle. The agent unloads `bmhook` and `tmhook` through `rmmod`, then reloads them. During that temporary window, behavior monitoring is absent or degraded, and I observed a normally blocked artifact being written to disk successfully.

The most accurate name for the issue is:

```text
Local temporary protection bypass via forced bmhook/tmhook reload.
```

The most important part is not that the module comes back. It does come back. The important part is that the gap can be induced and repeated by a local user.

From an attacker's perspective, a repeatable gap is enough. A payload does not need the endpoint to stay blind forever. It only needs a short moment where the product fails open while the attacker writes, renames, chmods, unpacks, or starts something that would normally be blocked or logged.
