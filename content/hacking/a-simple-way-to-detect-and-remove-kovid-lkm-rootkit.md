---
title: A simple way to detect and remove LKM rootkit KoviD 
image: https://i.imgur.com/xeSd64L.png
description: Learn a simple way on how to detect and remove Kovid rootkit.
categories: [Hunting]
tags: [Rootkit]
author: 0xMatheuZ
---

![imgur](https://i.imgur.com/Xd3Y153.jpeg)

Hello everyone, welcome to this post where I will cover the easiest way on how to detect and remove LKM KoviD rootkit.

But first of all, we need to understand how the KoviD works.

## What is KoviD?

KoviD is a Linux kernel rootkit, containing several features that make it difficult to detect and remove, in my opinion KoviD is the best open source LKM rootkit today, you can see more about it on [github](https://github.com/carloslack/KoviD).

Now that we know what KoviD is, we can analyze its code and see how it works, for example, which hooking method it uses.

### Ftrace hooking

![imgur](https://i.imgur.com/Lanlg4L.png)

Looking at KoviD [sys.c](https://github.com/carloslack/KoviD/blob/master/src/sys.c), we can see that it uses a very famous method for hooking syscalls that works very well on newer kernels, which is ftrace (function tracer).

Keep this information, it will be very useful later in this post.

### Setup KoviD and Loading.

According to the kovid readme, before compiling, we need to edit the Makefile to choose a unique file name for "/proc/name".

![imgur](https://i.imgur.com/OR0n9Zd.png)

After compiling using `make`, we can insert it using `insmod kovid.ko`.

![imgur](https://i.imgur.com/pZeUSA3.png)

After inserting it, we can see that /proc/mtz had not been enabled and also the module was not hidden after its insertion, so first it is necessary to enable /proc/mtz using ```kill -SIGCONT 31337``` and after that, hide the LKM from lsmod using ```echo -h >/proc/mtz```.

I also hid the file containing the name mtz, making it invisible in /proc/.

Well, after enabling /proc/mtz, we can look in dmesg that a random magic word was generated, and this magic word is used to make KoviD visible again.

![imgur](https://i.imgur.com/HCcI1tH.png)

In [kovid.c](https://github.com/carloslack/KoviD/blob/master/src/kovid.c#L337) we can see this magic word function being called to make the module visible again.

![imgur](https://i.imgur.com/azg1fh1.png)

### Detecting KoviD

Well, luckily for us, there is a filesystem that is not very well known, which is tracing, normally on more up-to-date systems, it is already mounted by default, if tracefs is not mounted, just mount it using ```mount -t tracefs nodev /sys/kernel/tracing```, and you can find its documentation at [kernel.org](https://www.kernel.org/doc/html/v6.5/trace/ftrace.html).

And in it we can simply view all the LKM functions that are loaded on the machine.

![imgur](https://i.imgur.com/iX13ILl.png)

A very interesting curiosity is that when Kovid is invisible, the trace only shows the addresses of each Kovid function (which in my head still doesn't make much sense, since the /sys/kernel/tracing/available_filter_functions_addrs file was only added in kernel 6.5x, in it we can view the addresses of each function of each loaded lkm too and I am using kernel 5.15.0-119-generic for testing).

Now, if we make kovid visible again, the name of its functions will appear.

![imgur](https://i.imgur.com/dsMqi2i.png)

This is a very simple way to detect KoviD, and it doesn't require much effort.

However, there is still a way to hide any function/LKM from the tracefs file system, so don't be fooled by that and don't think that if you didn't find anything there that you are safe. Maybe I'll talk about this in a future post.

You can also use [nitara2](https://github.com/ksen-lin/nitara2) to detect KoviD.

![imgur](https://i.imgur.com/7uWuNz6.png)

### Making KoviD hooks useless

This part is very interesting and you will learn a really cool trick (if you didn't already know).

Remember when I mentioned at the beginning of the post that KoviD uses ftrace as a hooking method? So, many people may not know that there is a way to disable ftrace with just one command.

```
echo 0 > /proc/sys/kernel/ftrace_enabled
or
sysctl kernel.ftrace_enabled=0
```

Okay, but what's so great about that? Well, let's go!

By temporarily disabling ftrace, all kovid hooks stop working, as it uses ftrace for hooking, but this still does not make kovid visible, but it makes it useless.

KoviD hides the file containing the name mtz, so /proc/mtz is hidden, and in it is the magic word to make LKM visible again.

![imgur](https://i.imgur.com/CywD6Ow.png)

Well now with ftrace disabled we can see that the hidden /proc/mtz has become visible as no kovid hook works as it uses ftrace as syscalls hook.

![imgur](https://i.imgur.com/3YyukDi.png)

So, after disabling ftrace, just go to /proc/mtz that was visible, get the magic word, and make LKM visible again, being able to remove it.

And this is the easiest way to detect/remove KoviD.

## Notes

1- Of course, this is not 100% effective, as it has a way of hiding from the tracefs filesystem, but against KoviD so far, this works perfectly.

2- And it is also obvious that in a real scenario, if someone is using KoviD, the name in /proc/name will not be something common like mtz, they would probably use a name that is less "imperceptible".

3- You can make any LKM rootkit that uses ftrace as hooking completely useless, and when you make it useless, you can use that to your advantage and analyze the compromised environment, looking for hidden PIDs, directories/files, etc.

## Final consideration

I hope you enjoyed this post and learned something, if you have any questions, please DM me on [Twitter](https://x.com/MatheuzSecurity).