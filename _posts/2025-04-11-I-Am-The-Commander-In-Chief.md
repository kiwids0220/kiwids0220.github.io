---
layout: post
title: I Am the Commander-in-chief
date: 2025-02-15
categories:
  - Notes
  - JTAG
  - Debugging
  - Reverse Engineering
tags:
  - notes
---

# Introduction

JTAG - IEEE standard (1149.1)  

Using JTAG for debugging Windows Internals...

## Prerequisites
 - UEFI Development Experience
	 - https://github.com/tianocore/tianocore.github.io/wiki/Build-Instructions
	 - https://github.com/tianocore/tianocore.github.io/wiki/How-to-Build-With-Stuart
		 - https://github.com/tianocore/tianocore.github.io/wiki/Build-Instructions#build-option-comparison
		 - https://github.com/docker/for-win/issues/13242
		 - `docker run -it --rm -v /home/kiwids/UEFIDev:/workspace --env=EDKREPO_URL=https://github.com/tianocore/edk2-edkrepo/releases/download/edkrepo-v2.1.2/edkrepo-2.1.2.tar.gz --env=DEBIAN_FRONTEND=noninteractive --env=TZ=UTC --env=GCC_MAJOR_VERSION=12 --env=VIRTUAL_ENV=/opt/venv --env=GCC5_AARCH64_PREFIX=/usr/bin/aarch64-linux-gnu- --env=GCC5_ARM_PREFIX=/usr/bin/arm-linux-gnueabi- --env=GCC5_RISCV64_PREFIX=/usr/bin/riscv64-linux-gnu- --env=LANG=en_US.UTF-8 --env=LANGUAGE=en_US:en --env=LC_ALL=en_US.UTF-8 --network=bridge --restart=no --label='org.opencontainers.image.ref.name=ubuntu' --label='org.opencontainers.image.version=22.04' --runtime=runc -d ghcr.io/tianocore/containers/ubuntu-22-build:latest`
		 - git submodule update --init
		 - 
		 - https://medium.com/@kartikaybhardwaj77/setting-up-and-running-edk2-on-windows-d579febab517
		 - `git config --global --add safe.directory '*'`
		 - Running QEMU

```
qemu-system-x86_64   -drive if=pflash,format=raw,readonly,file=c:/Users/kiwids/Documents/OVMF_CODE.fd   -drive if=pflash,format=raw,file=C:/Users/kiwids/Documents/OVMF_VARS.fd -drive format=raw,file=C:/Users/kiwids/Documents/uefi-app.img  -m 1024
```

 - Debugging
 - 

## In My Own Word
JTAG is a standard used by hardware engineers to troubleshoot/test the connections between ICs (integrated circuits) on PCB (printed circuit board) board 

Now it can interact with the statemachine inside of ICs to program, provide output.

4 Signals:
  - TDI > Chainning the ICs together : Think of it as ingress  into ICs
  - TDO > Outgress ICs
  - TMS > Wired in parallel with TCK
  - TCK > Wired in parallel with TMS

![[2025-04-11-I-Am-The-Commander-In-Chief-250412.png]]



## Windows Boot UEFI 
- SEC phase, verifies pre-EFI initialization modules
- PEI (pre-EFI)  switch processor to 64bit mode, search and executes device drivers 
- Secure Boot as DXE driver
- 
![[2025-04-11-I-Am-The-Commander-In-Chief-250414.png]]

#### GPT Partition
- EFI system (storing bootmgrfw.efi and memtest.efi, winsipolicy.p7b)
- recovery
- reserved for setup tool
- boot partition (NTFS)
#### Secure Boot
- To prevent malicious/untrusted UEFI firmware execute before the  Windows Boot Manager - (DXE drivers, UEFI boot managers, loaders and so on)

#### Booting
SEC  -> UEFI platform init -> DXE -> BDS - Bootmgrfw.efi ->  Winload.efi -> hvloader.dll -> hvix64.exe
##### Bootmgrfw.efi!BmMain
- init boot logger and basic system services
- init sec features (e.x., secure boot)
- reads BCD (boot config data store)
- creates a boot list 
- TPM and decrypt bitlocker
- pick and launch winrecovery or winload
###### Bootmgrfw.efi!bootenumpolicy
###### Bootmgrfw.efi!BmpProcessBootEntry
###### Bootmgrfw.efi!BmTransferExecution

###### Bootmgrfw.efi!
if user pressed F8 or F10, adds relative BCD element to the in-memory boot option list of the default boot application


##### Measured Boot
Measurement  referes to  a process of calculating a cryptographic hash of a partucular entity, code, data struct, config, anything loadable to memory.

##### Secure Kernels
Loaded by Winload 
Main function -> OslMain, called by Bootmanager.
## Refs
- [Windows Internal 7th Edition Part II Chapter 12]
- [# VT-rp, HLAT, and my AAEON Alder Lake Core i7-1270PE board: Part 1](https://www.asset-intertech.com/resources/blog/2024/09/vt-rp-hlat-and-my-aaeon-alder-lake-core-i7-1270pe-board-part-1/)
- [# VT-rp, HLAT, and my AAEON Alder Lake Core i7-1270PE board: Part 2](https://www.asset-intertech.com/resources/blog/2024/12/vt-rp-hlat-and-my-aaeon-alder-lake-core-i7-1270pe-board-part-2/)
- [# VT-rp, HLAT, and my AAEON Alder Lake Core i7-1270PE board: Part 3](https://www.asset-intertech.com/resources/blog/2025/01/vt-rp-hlat-and-my-aaeon-alder-lake-core-i7-1270pe-board-part-3/)
- [StackOverflow](https://stackoverflow.com/questions/21156135/how-is-a-jtag-used-as-a-debugger)
- [Debugging the undebuggable – Part 1
](https://www.andrea-allievi.com/blog/debugging-the-undebuggable-part-1/)
- [How to debug this black magic?] (https://www.andrea-allievi.com/blog/downgrade-attack-a-story-as-old-as-windows/)
	- It mentioned "Note that a lot of Code integrity code works only when Secure Boot is **on**. I have been able to install customized Secure boot keys in my QEMU virtual machine, and realized that in the AAEON board keys are already loaded by default, which mean that you can debug it (using the JTAG EXDI interface connected to SourcePoint) with Secure boot ON and witness also other WDAC policies being applied (like Secure Boot policies, which prevents the enablements of classical kernel debuggers"
