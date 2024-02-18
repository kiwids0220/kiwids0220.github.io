---
layout: post
title: Debugging kAFL, A Snapshot-based Fuzzer - Part II
date: 2024-02-13
categories: [Virtualization, QEMU-NYX, kAFL]
tags : [fuzz]
---
### QEMU references

### Getting a full system dump while fuzzing

The kAFL patches the monitor/GUI interface when it starts, so we can't really utilize the qemu monitor command line to snatch a full system memory dump while the fuzzer is running.

### Pausing Fuzzer and Collecting memory dump

You can technically "pause" the fuzzer and get your system dump there. 

To make sure the Windows guest vm is able to collect a full system memory dump in QEMU, we need to make sure that it installs the `FwCfg driver` which is included in the `virt-io` ISO installer, for more detailed instruction, I found this blog very helpful [Guest Windows debugging and crashdumping under QEMU/KVM: dump-guest-memory, vmcoreinfo and virtio-win](https://daynix.github.io/2023/02/19/Guest-Windows-debugging-and-crashdumping-under-QEMU-KVM-dump-guest-memory-vmcoreinfo-and-virtio-win.html)

Well the trick to "pause" the fuzzer is simply reapplying what I talked about in the [Part I ]({{ site.baseurl }}{% post_url 2024-01-31-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER %}) with another trick - using socat. The details is documented [QEMU monitor with socat](https://unix.stackexchange.com/questions/426652/connect-to-running-qemu-instance-with-qemu-monitor).

Here is how you do it:
- We are still gonna run the same command line argument with our GDB/Pwndbg, but this time adding `-device vmcoreinfo --monitor unix:qemu-monitor-socket,server,nowait` at the end
  
```
gdb --args "./x86_64-softmmu/qemu-system-x86_64" -enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -net none -display none -chardev socket,server,id=nyx_socket,path=/tmp/kafl_kiwi/interface_0 -device nyx,chardev=nyx_socket,workdir=/tmp/kafl_kiwi,worker_id=0,bitmap_size=65536,input_buffer_size=131072 -device isa-serial,chardev=kafl_serial -chardev file,id=kafl_serial,mux=on,path=/tmp/kafl_kiwi/serial_00.log -m 4096 -drive file=/home/kiwi/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img -fast_vm_reload path=/tmp/kafl_kiwi/snapshot/,load=off -device vmcoreinfo --monitor unix:qemu-monitor-socket,server,nowait
```
- Kick off kAFL fuzzer frontend (patching out the subprocess.run that kick off another QEMU instance because we are doing it with gdb already)
- After the fuzzing loop starts, hit `Crtl + C` in gdb
- Go into the gdb directly, and connect to the QEMU monitor using `socat -,echo=0,icanon=0 unix-connect:qemu-monitor-socket`
- Run `dump-guest-memory -w memory.dmp` in the monitor CLI
- Continue the execution in gdb 

After that you should be able to collect a full system dump 

![](/assets/images/2024-01-31-systemdump.png)

