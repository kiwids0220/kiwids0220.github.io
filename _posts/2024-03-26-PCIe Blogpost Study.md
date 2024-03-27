---
layout: post
title: PCIe Study Notes
categories: Notes
tags:
  - notes
---

## The Credit Goes To

[A Practical Tutorial on PCIe for Total Beginners on Windows (Part 1)](https://ctf.re/windows/kernel/pcie/tutorial/2023/02/14/pcie-part-1/)

## PCIe Study Notes

### ACPI x64-based PC 

PCIe bus is not the initial layout of the system presented by firmware during boot. ACPI (Advanced Configuration & Power Interface) is what describes the existence of PCIe to the OS. 

### PCIe Tree Root Complex
#rootcomplex
The PCI Express Root Complex
![](/assets/images/03-26-20242024-03-26-PCIe%20Blogpost%20Study.png)

#### PCI Express Root Port
Similar to a port on motherboard 
A port that another PCIe Endpoint or PCIe Switch can be connected to.
- An Endpoint ( a physical device - Type 0)
	- configured as a device to talk to
- A Switch (a Bridge device - Type 1)
	- other is configured as a device to route packets
- **Root Complex Integrated Endpoints** (RCIE, Marked in Green below) since they are intergrated directly on the **Root Complex** 
![](/assets/images/03-26-20242024-03-26-PCIe%20Blogpost%20Study-2.png)

#### Bus/Device/Function
##### Bus
#bdf
- All busses on the system are identified with a number (0-255)
- Bus/Device/Function identifies where in the PCIe hierarchy the device is located so we can communicate with it.
- Bus "0" lcoated on the **silicon of the CPU***
- 
![](/assets/images/03-26-20242024-03-26-PCIe%20Blogpost%20Study-6.png)
Ex. Bus 0
![](/assets/images/03-26-20242024-03-26-PCIe%20Blogpost%20Study-3.png)
Ex. Bus 1 (under a Root )
![](/assets/images/03-26-20242024-03-26-PCIe%20Blogpost%20Study-5.png)
##### Device 
- Device ID represents a physical device 

##### Function
- Function ID represents the distinct capablity the physical device supports and expose to the system
- A device that exposes more than one function is a **Multi-Function Device (MFD)*** - More PCI connections (e.x., NVIDIA GEFORCE RTX 4070TI and NVIDIA HIGH DEFINITION AUDIO devices)
- 