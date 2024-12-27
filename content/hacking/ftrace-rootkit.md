---
title: Detecting rootkits based on ftrace hooking.
image: https://i.imgur.com/xeSd64L.png
description: Learn how to detect rootkit based on ftrace hooking.
categories: [Forensics]
tags: [Rootkit]
author: 0xMatheuZ
---

Hello! Welcome to this post! Well, I have a server that is focused on rootkit research, both for Linux and Windows, feel free to come and participate in our community.

- https://discord.gg/66N5ZQppU7

## What is Ftrace?

ftrace (Function tracing) is a kernel function tracer. It helps a lot with debugging the Linux kernel, tracing functions, events, and of course, you can use ftrace to do hooking, etc.

Main Features:

- Function Tracing: Records kernel function calls, including order and execution time.
- Event Tracing: Monitors system events.
- Custom Filters: Focus on specific functions or events via configuration files.
- Support for dynamic tracers like kprobes and integration with tools like perf.

On more current systems, tracing is enabled by default, but if not, simply set it:

- mount -t tracefs nodev /sys/kernel/tracing

## Ways to detect ftrace-based rootkits

Detecting an LKM rootkit that uses ftrace is actually easier than you might think. If a rootkit uses ftrace, it is automatically detectable, because currently (at the time I am writing this post) there is no rootkit that I have seen that can hide from some tracing features.

I will use the dreaded `KoviD` rootkit that uses ftrace as hooking.

![imgur](https://i.imgur.com/dEiswVE.png)

Now with `KoviD` loaded and hidden, we can begin.


![imgur](https://i.imgur.com/kmWU2Wj.png)

`KoviD` can be easily detected in `/sys/kernel/tracing/enabled_functions`, this file basically lists the kernel functions currently enabled for tracing.

![imgur](https://i.imgur.com/prJ8VFb.png)

`KoviD` can also be detected in `/sys/kernel/tracing/touched_functions`, this file shows all functions that were every traced by ftrace or a direct trampoline (only for kernel 6.4+)

![imgur](https://i.imgur.com/0DAZqBg.png)

in the current version of `kovid`, its functions do not appear in `/sys/kernel/tracing/available_filter_functions`, but it still leaves traces in this file, which basically lists kernel functions that can be filtered for tracing.

No ftrace based rootkit that I have seen so far can hide 100% and can be easily found, they always leave some trace behind.

You can also check my github repository, it contains several really cool things to detect and remove modern rootkits.
### [**Cheat sheet: Detecting and Removing Linux Kernel Rootkit**](https://github.com/MatheuZSecurity/detect-lkm-rootkit-cheatsheet)

