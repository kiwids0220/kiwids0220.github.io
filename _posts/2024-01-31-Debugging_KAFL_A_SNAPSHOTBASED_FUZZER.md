---
layout: post
title: Debugging kAFL, A Snapshot-based Fuzzer - Part I
date: 2024-01-31
categories: [Virtualization, QEMU-NYX, kAFL]
tags : [fuzz]
---
### kAFL 

Right of the bat, these sources act as the single sources of truth if you want to get a deeper understanding of kAFL:
[kAFL White Paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)
[kAFL Doc](https://intellabs.github.io/kAFL/tutorials/introduction.html)


### What's the blogpost about?

Recently, I wanted to dive into the world of fuzzing, espcially kernel fuzzing, which is what led me to this project. I knew nothing about Fuzzing, what's a fuzzer, harness, corpus, frontend, backend, mutator, snapshot-based fuzzing. None of these made sense to me, so kAFL is the perfect project for me to dive in and learn about all those concepts.

I wanted to utilize kAFL to fuzz Windows kernel drivers/core system component, but while the Github repo provided a great example for both fuzzing against the kernel mode target and the user mode target, I still find myself stuck in a suitiation where the fuzzer does not work the way I inteded. Well, the most important question is, how do we figure it out? The only answer is to start debugging..


### Infrastructure

The white paper ^ has nice explanation for kAFL's internal infrastructure, you can also find it on their github 

### Debugging the frontend
 The frontend fuzzer kAFL itself is written in Python, and the vscode is prob the best option here to debug anything in Python. So I find the `__main__.py` and put a couple breakpoints
![mainPy](/assets/images/main.py-1.png)
Upon creating the Python debug configuration file and launching it with argument `fuzz --afl` , it hits those breakpoints but I was unable to continue to debug because the function `qemu._connect()` will fail because of a socket error. It turns out the frontend python script is communicating to the QEMU instance via `UNIX Socket` as documented in the kAFL documentation.

![](/assets/images/2024-01-31-QEMU-connect.py.png)
[Doc](https://intellabs.github.io/kAFL/reference/workdir_layout.html)
```
├── interface_N                  - socket between kAFL worker N and Qemu N
```

### We would love to debug the QEMU instance as well
As you see in the screenshot above, I have commented out the `subprocess` which will start a new `QEMU-Nyx` process that boots our image. while QEMU provides useful stub `-S, -s` for pausing the VM image at it's first vCPU execution, we would still love to pause the QEMU process at the initialization phase (i.e., Machine/CPU/Peripheral initializatio) which is the actual `main()` function in `vl.c` file (QEMU 4.2.0 release).

So, we can tell the python script to pause at `qemu.connect()` and then start the QEMU-Nyx instance ourself -> wait for the socket to listen for connection -> continue the frontend fuzzer -> we can now continue the debugging process

To achieve this, I leveraged `debugpy` which is what vscode uses under the hood for python debugging, to listen on a port at the begining of the `start()` function of QEMU python class

![](/assets/images/2024-01-31-Start.png)

And the configuration file
![](/assets/images/2024-01-31-config-port.png)


### Building QEMU-Nyx yourself

If you look at the repo [QEMU-Nyx](https://github.com/nyx-fuzz/QEMU-Nyx), you will see it included a [.sh](https://github.com/nyx-fuzz/QEMU-Nyx/blob/qemu-nyx-4.2.0/compile_qemu_nyx.sh) script to build the QEMU-Nyx with a few options 
![](/assets/images/2024-01-31-compilesh.png)
Here is the actual flags being passed to configure
![](/assets/images/2024-01-31-compileflag.png)

This is done so that we can get the full symbol for the `qemu-system-x86_64` and start debugging with `gdb`.


### Putting it together

Follow the procedure of building your vm image using vagrant and ansible playbook -> start the fuzzer with `kafl fuzz --purge -w /tmp/whatever`  (-w for setting the working directory) -> make sure the interface_0 unix socket exist in the folder, attach to the python script debugpy and start debugging.



![](/assets/images/2024-01-31-QEMU-Nyx%20handshake.png)![](/assets/images/2024-01-31-pwndbg.png)