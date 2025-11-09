---
title: "Ioctl Secrets Writeup"
description: Solving an easy reversing challenge from rootkit researchers.
categories: [Reversing]
tags: [CTF]
author: 0xMatheuZ
images:
  - "https://i.imgur.com/ZTjHU7a.jpeg"
---

![img](https://i.imgur.com/ZTjHU7a.jpeg)

---

## Challenge Description

In this challenge, we're given access to a Linux virtual machine (VM) running Ubuntu. The objective is to exploit a custom kernel module to retrieve a hidden flag. The challenge involves reverse engineering, kernel internals, and crafting a proper exploit.

**What we have:**
- A hidden kernel module loaded at boot
- Character device at `/dev/ioctl_dev`
- Setup script (`device.sh`) that loads the module and shreds source files
- SSH access enabled (username: `root`, password: `ioctl`)

**Important Note:** Many participants had difficulties copy-pasting code directly into the VM console. As stated in the challenge description, **SSH is enabled** for easier interaction! This was a common pain point, so let's start by addressing it.

---

## Getting Started - VM Access & SSH

When you boot the VM, you'll see the login screen. The credentials are straightforward:

- **Username:** `root`
- **Password:** `ioctl`

### Setting Up SSH Access

After logging in, the first thing you should do is check the VM's IP address to enable SSH access. This makes the challenge much more comfortable as you can:
- Copy and paste code easily
- Use multiple terminal windows
- Access from your preferred terminal emulator

Run `ip a` to get the network configuration:

As we can see, the VM has IP `192.168.200.165`. Now we can SSH from our host machine:

```bash
ssh root@192.168.200.165
```

![SSH Connection](https://i.imgur.com/HjDAVom.png)

---

## Initial Reconnaissance

Now that we're comfortably connected via SSH, let's explore what we have on the system.

### Checking for the Device

The challenge mentions a device at `/dev/ioctl_dev`. Let's verify it exists:

```bash
root@hunter:~# ls -lah /dev/ioctl_dev
crw------- 1 root root 237, 0 Nov 9 16:15 /dev/ioctl_dev
```

![Device File](https://i.imgur.com/6NkOMLc.png)

Perfect! The device exists with:
- **Type:** Character device (`c`)
- **Permissions:** root only
- **Major number:** 237
- **Minor number:** 0

## Reverse Engineering the Kernel Module

Time to analyze the kernel object (device.ko)! I'll be using binary ninja for this, but Ghidra or IDA work just as well.

### Loading device.ko into binary ninja

After loading `device.ko` into binary ninja and letting it analyze, we can see several interesting functions in the symbol:

Key functions identified:
- `ioctl_handler` - The main function we need to understand
- `init_module` - Module initialization
- `hide` - Module hiding functionality
- `cleanup_module` - Module cleanup

### Analyzing ioctl_handler()

This is where the magic happens! Let's examine the decompiled code:

![ioctl_handler Code](https://i.imgur.com/bipyxZi.png)

```c
int64_t ioctl_handler() {
    int64_t rdx_2;
    int32_t rsi_3;
    rdx_2 = __fentry__();
    void* gsbase;
    int64_t rax = *(uint64_t*)((char*)gsbase + 0x28);
    int32_t var_7c;
    int32_t var_78;
    
    if (rsi_3 == 0xc0487213 && 
        !_copy_from_user(&var_7c, rdx_2, 0x48) &&
        var_7c == 0x1337dead && 
        var_78 == 0xcafebabe)
    {
        int64_t var_74;
        __builtin_strncpy(&var_74, "ROOTKIT{fake_flag_for_you}", 0x1b);
        _copy_to_user(rdx_2, &var_7c, 0x48);
    }
    
    if (rax == *(uint64_t*)((char*)gsbase + 0x28))
        return __x86_return_thunk();
    
    __stack_chk_fail();
}
```

**findings:**

1. **ioctl Command Check:** `rsi_3 == 0xc0487213`
   - This is the ioctl request number we need to use

2. **Buffer Size:** `_copy_from_user(&var_7c, rdx_2, 0x48)`
   - Expects exactly `0x48` bytes (72 bytes)

3. **Magic Value #1:** `var_7c == 0x1337dead`
   - First 4 bytes must be `0x1337DEAD`

4. **Magic Value #2:** `var_78 == 0xcafebabe`
   - Next 4 bytes must be `0xCAFEBABE`

### Understanding the init_module()

Let's also check how the device gets created:

![init_module Code](https://i.imgur.com/GSLBhPr.png)

```c
int64_t init_module() {
    __fentry__();
    uint32_t rax = __register_chrdev(0, 0, 0x100, "ioctl_dev", &fops);
    major = rax;
    
    if (rax >= 0) {
        uint64_t rax_1 = __class_create(&__this_module, "ioctl_class", &__key.2);
        ioctl_class = rax_1;
        
        if (rax_1 <= -0x1000) {
            uint64_t rax_3 = device_create(rax_1, 0, (uint64_t)(major << 0x14), 0, "ioctl_dev");
            __key.2 = rax_3;
            
            if (rax_3 <= -0x1000) {
                hide();
                _printk(0x400326);
            }
        }
    }
    
    return __x86_return_thunk();
}
```

The `device_create()` call creates our `/dev/ioctl_dev` device with:
- Device class: `ioctl_class`
- Device name: `ioctl_dev`
- Major number: dynamically allocated (237 in our case)

After successful creation, it calls `hide()` to make the module invisible to `lsmod`.

---

## Writing the Exploit

Now that we understand the requirements, let's write our exploit code!

### The Exploit

1. Create a 72-byte buffer
2. Write `0x1337DEAD` at offset 0
3. Write `0xCAFEBABE` at offset 4
4. Open `/dev/ioctl_dev`
5. Call ioctl with command `0xc0487213`
6. Read the flag from the returned buffer

### exploit.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>

int main() {
    int fd;
    char buf[0x48];
    uint32_t val1 = 0x1337DEAD;
    uint32_t val2 = 0xCAFEBABE;
    
    memset(buf, 0, sizeof(buf));
    *(uint32_t*)buf = val1;
    *(uint32_t*)(buf + 4) = val2;
    
    fd = open("/dev/ioctl_dev", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    if (ioctl(fd, 0xc0487213, buf) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }
    
    printf("Flag: %s\n", buf);
    
    close(fd);
    return 0;
}
```

### Compiling and Running

Since we're connected via SSH, we can easily copy the code and compile it:

```bash
root@hunter:~# gcc exploit.c -o exploit
root@hunter:~# ./exploit
```

![Exploit Execution](https://i.imgur.com/uRb9EAY.png)

```
Flag: ROOTKIT{ioctl_secret_unlocked@1337}
```

**Success!** We've captured the flag!

### Why It Works

The exploit works because the kernel module uses the same buffer for both receiving input and sending output. We create a 72-byte buffer (buf[0x48]), write the magic values 0x1337DEAD and 0xCAFEBABE at the beginning using pointer casting (*(uint32_t*)buf), then open the device and call ioctl() with command 0xc0487213. 

The kernel validates our magic values with _copy_from_user(), and if they match, uses _copy_to_user() with the same pointer to overwrite our buffer with the flag.

---

## Key Lessons Learned

### 1. Check dmesg for Kernel Activity
Kernel messages provided crucial information about module loading and potential issues.

### 2. Understand ioctl Communication
The ioctl interface is a powerful way for userspace to communicate with kernel drivers. Understanding the command numbers and data structures is essential.

### 3. Reversing Skills
Being comfortable with tools like Ghidra, IDA, or Binary Ninja is crucial for kernel module analysis.

---

## Conclusion

This challenge was an excellent introduction to Reversing and you can learn:

- Linux kernel modules  
- Reverse engineering 
- Crafting ioctl requests  
- Recognizing rootkit techniques  

---

## Our Community

Join the **RootKitSecrets** community:  
[Discord Server](https://discord.gg/66N5ZOpqU7)

*Challenge created by Matheuz - Have fun guys!!*

---

**Thanks for reading! If you enjoyed this writeup, consider sharing it with others who might find it useful. Happy hacking!**