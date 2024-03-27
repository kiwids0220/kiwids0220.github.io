---
layout: post
title: Migrating HyperV Gen2 Windows 11 VM To Proxmox
categories: [HyperV]
tags:
  - devops
  - HyperV
  - Proxmox
---

## Prep Work On Windows 11 VM
1. Make sure to turn off "Secure Boot" option in HyperV Management Console
2. Convert multiple disk partitions into single disk
3. Convert the disk into QEMU compactible format (https://www.starwindsoftware.com/blog/how-to-convert-hyper-v-to-kvm-vm)


## Proxmox VM Creation
1. Create a VM in Proxmox, OS Setting
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox.png)
2. Change the Machine type to `q35` essentially QEMU will initiate a machine type of q35 with default emulated/virtualized devices
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox-1.png)
3. Change the disk size to 1 GB
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox-3.png)
4. Your preference on CPU, Memory, Network


## Import The Image 
1. Move the converted image to Proxmox server 
2. run `qm disk import PATH_TO_IMAGE VMID STORAGE`
	- In this case, I have created storage for all my vm images and called it `runimages`.
	- I also created the VM described above with a unique VMID `999`
	- So in this case, the command turns into `qm disk import PATH_TO_IMAGE 999 runimages`

## Modifying The Imported Image
1. Remove the previous configured disk (i.e, 1 GB disk during VM creation)
	- Should look like this 
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox-4.png)
2. Change the "Boot Order" to select our imported disk
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox-5.png)


## Done!
![](/assets/images/03-26-20242024-03-26-Migrating%20HyperV%20Gen2%20Windows%20VM%20To%20Proxmox-6.png)