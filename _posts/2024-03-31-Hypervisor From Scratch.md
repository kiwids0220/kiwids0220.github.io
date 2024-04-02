---
layout: post
title: Hypervisor From Scratch 
date: 2024-03-31
categories: [Notes, Hypervisors]
tags:
  - notes
  - Hypervisors
---

## Intel VT-x operations

### Detect VMX Support
#virtualmachineextension #vmx
```c

//23.6 DISCOVERING SUPPORT FOR VMX

bool
DetectVmxSupport()
{
    bool VMX = false;
    __asm {
		XOR    EAX, EAX
		INC    EAX
		CPUID
		BT     ECX, 0x5
		JC     VMXSupport
		VMXNotSupport :
		JMP     NopInstr
		VMXSupport :
		MOV    VMX, 0x1
		NopInstr :
		NOP
    }

    return VMX;
}
```



#### User-mode Buffer To Kernel-mode 
- METHOD_BUFFERED - `Irp->AssociatedIrp.SystemBuffer`
- METHOD_IN_DIRECT and METHOD_OUT_DIRECT  - `Irp->AssociatedIrp.SystemBuffer` , the I/O manager is in charge of allocating a **system buffer** and set the `irp->associatedirp.systembuffer` and copies the content of user input buffer into the System Buffer.
- METHOD_NIETHER - `Parameters.DeviceIoControl.Type3InputBuffer`
	- in `IO_STACK_LOCATION `. Output buffer -> `Irp->UserBuffer.`
	- Buffer size `Parameters.DeviceIoControl.InputBufferLength and Parameters.DeviceIoControl.OutputBufferLength`
	- **Accessing** the buffer goes

```c

InBuf  = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
OutBuf = Irp->UserBuffer;

try
    {
		ProbeForRead(InBuf, InBufLength, sizeof(UCHAR));
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
	 NtStatus = GetExceptionCode();
		DbgPrint(
			"Exception while accessing InBuf 0X%08X in METHOD_NEITHER\n",
			NtStatus);
		break;
	
	}
Mdl = IoAllocateMdl(InBuf, InBufLength, FALSE, TRUE, NULL);
try
	{

		MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		NtStatus = GetExceptionCode();
		DbgPrint((
			"Exception while locking InBuf 0X%08X in METHOD_NEITHER\n",
			NtStatus));
		IoFreeMdl(Mdl);
		break;
	}
//map the address to system space and read it
Buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);
//after reading, unlock and unmap 
MmUnlockPages(Mdl);
IoFreeMdl(Mdl);

```

![](/assets/images/03-31-20242024-03-31-Hypervisor%20From%20Scratch-1.png)
```c
#define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)

#define IOCTL_TEST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
### Creating Custom Virtual Machine Monitor (VMM)

#vmm
- There should be equal numbers of VMCSs and VMXON regions as the number of logical processors.
- Check if VMX operations are supported

```c
BOOLEAN
IsVmxSupported()
{
    CPUID Data = {0};
    //
    // Check for the VMX bit
    //
    __cpuid((int *)&Data, 1);
    if ((Data.ecx & (1 << 5)) == 0)
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = {0};
    Control.All                      = __readmsr(MSR_IA32_FEATURE_CONTROL);
    //
    // BIOS lock check
    //
    if (Control.Fields.Lock == 0)
    {
        Control.Fields.Lock        = TRUE;
        Control.Fields.EnableVmxon = TRUE;
        __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
    }
    else if (Control.Fields.EnableVmxon == FALSE)
    {
        DbgPrint("[*] VMX locked off in BIOS");
        return FALSE;
    }
    return TRUE;
}
```
- Allocating VMCS and VMXON regions
```c

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;
VIRTUAL_MACHINE_STATE * g_GuestState;

BOOLEAN
InitializeVmx()
{
    if (!IsVmxSupported())
    {
        DbgPrint("[*] VMX is not supported in this machine !");
        return FALSE;
    }

    ProcessorCounts = KeQueryActiveProcessorCount(0);
    g_GuestState    = ExAllocatePoolWithTag(NonPagedPool,
                                         sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCounts,
                                         POOLTAG);

  
    KAFFINITY AffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        DbgPrint("AffinityMask %lx", AffinityMask);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);
        AsmEnableVmxOperation();
/*
AsmEnableVmxOperation PROC PUBLIC

	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET

AsmEnableVmxOperation ENDP
*/
        DbgPrint("[*] VMX Operation Enabled Successfully !");
    //Allocating contiguous memory for VMCS and VMXON, https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_memory_caching_type
      //  AllocateVmxonRegion(&g_GuestState[i]);
        // AllocateVmcsRegion(&g_GuestState[i]);
    }

    return TRUE;
}
```
- `CR0.PE, CR0.NE, CR0.PG, and CR4.VMXE` bit should be 1 to be executed in page-protected mode
- Writing the `Revision Identifier` from `IA32_VMX_BASIC_MSR` to VMXON Region

```c
typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;  // [0-30]
        ULONG32 Reserved1 : 1;            // [31]
        ULONG32 RegionSize : 12;          // [32-43]
        ULONG32 RegionClear : 1;          // [44]
        ULONG32 Reserved2 : 3;            // [45-47]
        ULONG32 SupportedIA64 : 1;        // [48]
        ULONG32 SupportedDualMoniter : 1; // [49]
        ULONG32 MemoryType : 4;           // [50-53]
        ULONG32 VmExitReport : 1;         // [54]
        ULONG32 VmxCapabilityHint : 1;    // [55]
        ULONG32 Reserved3 : 8;            // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;

IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;
```

- `AllocateVmxonRegion` , writes the `IA32_VMX_BASIC_MSR.Fields.RevisionIdentifier` to VMXON region and  turn VMXON

```c
BOOLEAN
AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE * GuestState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = {0};
    PhysicalMax.QuadPart         = MAXULONG64;

    int    VMXONSize = 2 * VMXON_SIZE;
    BYTE * Buffer    = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = {0}, Lowest = {0};
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_on(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", Status);
        return FALSE;
    }

    g_GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}
```

- `AllocateVmxonRegion` , writes the `IA32_VMX_BASIC_MSR.Fields.RevisionIdentifier` to VMCS region and  `VMPTRLD ` sets the current VMCS on a logical processor.
	- `vmptrst(PA)` sets the current VMCS at the specified PA

```c
BOOLEAN
AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE * GuestState)
{
    //
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    //
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = {0};
    PhysicalMax.QuadPart         = MAXULONG64;

    int    VMCSSize = 2 * VMCS_SIZE;
    BYTE * Buffer   = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = {0}, Lowest = {0};
    Highest.QuadPart = ~0;

    // BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);
    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (BYTE *)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (BYTE *)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx", Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx", AlignedPhysicalBuffer);

    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = {0};

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

    // Changing Revision Identifier
    *(UINT64 *)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", Status);
        return FALSE;
    }

    g_GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}
```
- Turn off VMX

```c
VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    KAFFINITY AffinityMask;
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %d th logical processor.", i);

        __vmx_off();
MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}

```
#### VMCS

##### Active vs. Current 
- There might be several VMCSs simultaneously in a processor, but just one of them is currently active
- 
##### VMCLEAR, VMPTRLD, VMREAD, and VMWRITE instructions.
- VMLAUNCH, VMREAD, VMRESUME, and VMWRITE instructions operate only on the current VMCS
	- VMLAUNCH can only execute if the VMCS is cleared
	- VMCLEAR can only execute on VMCS that's launched.
![](/assets/images/04-01-20242024-03-31-Hypervisor%20From%20Scratch.png)
#### Resources

https://github.com/DarthTon/HyperBone/tree/master

https://github.com/tandasat/HyperPlatform