---
layout: post
title: Deep Diving into Nyx Part I - The Setup
date: 2024-02-19
categories:
  - Virtualization
  - Nyx
  - Internal
tags:
  - fuzz
---
# The Setup
## Clone & Compare

I figured the best way to learn what modification that the `Nyx` has made on top of QEMU is to cloning both repos and compare all files that has been modified/added/deleted. To do so, I used a visual studio code extension `Diff Folders`  (Extension ID: `L13RARY.l13-diff`)

>NOTE: The Nyx QEMU is based off of QEMU 4.2.0, which you can find the in branch named `stable-4.2` 
>Here is the command line used to clone the repo `git clone -b stable-4.2 https://github.com/qemu/qemu.git` for QEMU
>`git clone https://github.com/nyx-fuzz/QEMU-Nyx.git` for QEMU-Nyx
{: .prompt-tip }

After that, should be easy to compare all the files that `Nyx` has added or modified, for example `Capstonev4`, `Nyx` folders appear as added folders
![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1.png)
![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-1.png)


## Where Can I Start?

Well, following my [Debugging kAFL series]({{ site.baseurl }}{% post_url 2024-01-31-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER %}), you know we have a example that we can debug and now it's just a matter of stepping through the source code and learn some more about `QEMU` and `Nyx` (two bird with one stone).

This time, I will not use `GDB` to debug but rather I will use VSCode to play on easy mode... The setup is quite simple, compile the `QEMU-Nyx` with 
```sh
┌[kiwish-4.2]-(Downloads/QEMU-Nyx)-[git:qemu-nyx-4.2.0*]-
└> ./compile_qemu_nyx.sh debug_static
```

Adding a configuration file into VS Code is simple enough, ask ChatGPT to convert out previous GDB command line to VS Code configuration
```json
{
    "version": "0.2",
    "configurations": [
        {
            "name": "QEMU Debugging",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/x86_64-softmmu/qemu-system-x86_64",
            "args": [
                "-enable-kvm",
                "-machine", "kAFL64-v1",
                "-cpu", "kAFL64-Hypervisor-v1,+vmx",
                "-no-reboot",
                "-net", "none",
                "-display", "none",
                "-chardev", "socket,server,id=nyx_socket,path=/tmp/kafl_kiwi/interface_0",
                "-device", "nyx,chardev=nyx_socket,workdir=/tmp/kafl_kiwi,worker_id=0,bitmap_size=65536,input_buffer_size=131072",
                "-device", "isa-serial,chardev=kafl_serial",
                "-chardev", "file,id=kafl_serial,mux=on,path=/tmp/kafl_kiwi/serial_00.log",
                "-m", "4096",
                "-drive", "file=/home/kiwi/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img",
                "-fast_vm_reload", "path=/tmp/kafl_kiwi/snapshot/,load=off",
                "-device", "vmcoreinfo",
                "--monitor", "unix:qemu-monitor-socket,server,nowait"
            ],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerPath": "/usr/bin/gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ]
        }
    ]
}
```

## Okay, Client

We can now run the `QEMU-Nyx`  by starting the debug session, and set a break point at `main()` in `vl.c` 
![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-3.png)
In VSCode debug mode and we will now get all the symbol information and the ability to inspect variables within VS Code. Shoutout to Microsoft VSCode dev team!
![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-2.png)

Well, we got our QEMU-Nyx running, but it's still waiting on a actual `client` to supply the corpus and instruct the QEMU-Nye instance what to do.

We will again use kAFL as our "QEMU-Nyx client" to initiate all workflow for us so we can focus on debugging the `QEMU-Nyx`. If you don't know how to do that yet, please check the blogpost linked above.
>NOTE: When you try to inspect `Global variables` , you will need to add them to the `Watch` tab. Ex. `global_state` variable, right click on the variable and `Add to Watch`.
{: .prompt-tip }

> NOTE:  I had this trouble when I was inspecting the `global_state` global variable, but however, VS Code mapped the variable to another struct that's in the original QEMU source code and I had to rename the Nyx's global_state variable to something else to avoid name collision
>  {: .prompt-warning }


# Putting Everything Together

1. Start the kAFL Fuzzer frontend 
	![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-4.png)
2. Start the QEMU-Nyx 
	![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-5.png)
3. Continue the execution of `QEMU-Nyx` and check the `workdir`to see if the `interface_X` socket is there. This is needed by kAFL to initialize the client handshake.
	![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-6.png)
4. Set desired breakpoints in QEMU-Nyx and continue kAFL execution. Ex. I set a breakpoint at nyx_interface device_realize function
	![](/assets/images/02-19-20242024-02-19-Nyx-Deep-Dive-Part-1-7.png)
5.  Have fun learning about QEMU and Nyx