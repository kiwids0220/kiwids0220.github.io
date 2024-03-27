---
layout: post
title: NT Filesystem Internals Study Notes
date: 2024-03-04
categories: [notes, NT FileSystem]
tags:
  - notes
---

# Notes 

### Spin Locks

- Spin lock are used to lock shared data to make sure there’s only one thread executed by one processor to access it.

- Dispatcher objects are provided by the kernel to the Executives

Dispatch Obj vs Spin lock:

- Spin lock will keep trying to require the lock, dispatcher object will put the thread to suspended state

Mutex vs Event

-  Event doesn’t provide the mutual exclusiveness between threads executed by processors while Mutex and Spin locks do 


# NT I/O Manager

- ## Execution Context
	- the kernel driver's code may be executed by many other threads outside of the context of the driver
	- This is important because depending on their context, they might not have access to other resources or have knowledge of.

	- ***The Context of a user-mode thread that has requested system services*** : the code will often execute in the context of the user-mode thread that requests any I/O operations (e.x., Read File)

	- ***The context of the dedicated worker thread created by the drive***, or by some kernel-mode component. They can do so by invoking `PsCreateSAystemThread()`.

	- ***The context of system worker threads specially created by the I/O manager to serve I/O subsystem components***. Usually happens in the `Async I/O requests`. from user-mode applications. The request will be picked up and handled by a system worker thread and upon finish it will notify the application.


 - ## Async I/O
	 - Allows thread to request I/O operations and continue performing other tasks until previously requested I/O have been completed.
		   ![](/assets/images/03-04-20242024-02-19-NT%20Filesystem%20Internals%20Study%20Notes-1.png)
		   
	- Interrupt and Preemptible
		- The Windows NT operating system associates execution priorities with threads which allows them to be **preempted*** by the NT Scheduler.
	- Objects and Handles
		- NT kernels create and holds the actual ***Objects***, while NT Executives exports them through **Handlers***, Kernel-mode drivers can use either ***a pointer to the object*** or **using object handle***

- ## Loading Driver
	- I/O manager calls `IopLoadDriver()`
	- Examining a global linked list of loaded kernel modeuls.
	- Not loaded? map the driver executable.
	- I/O manager invokes Object Manager requesting a new **driver object*** to be created.
	- I/O manager zeros out the driver object struct returned by `Object Manager`
	- `DriverObject.DriverInit` -> populates to `Driver->DriverEntry` 
	- I/O Manager requests that the object be inserted into the linked list of driver objects maintained by `Object Manager` NOTE:  IO Manager will get a handle to the object and ***reference it, close the object. Keeps the object in memory until it's derefed at driver unload time*** 
	- Calls `DriverEntry()` at `IRQL_PASSIVE_LEVEL` in the thread context under the system process. NOTE:  Any handles created during this will be only accessible in the context of the system process. If you want to use it later, you would need to capture the ***a pointer to the object*** and calls

- ## Driver Extension - Plug and Play
	- https://www.vergiliusproject.com/kernels/x86/Windows%20XP/SP3/_DRIVER_EXTENSION

  - FastIoDispatch, a way to avoid slow method o using packet-based I/O by allowing NT I/O Manager to **directly invoke** the file system dispatch routines without IRP structure.


```c
typedef struct _DRIVER_OBJECT {
  CSHORT             Type;
  CSHORT             Size;
  PDEVICE_OBJECT     DeviceObject;
  ULONG              Flags;
  PVOID              DriverStart;
  ULONG              DriverSize;
  PVOID              DriverSection;
  PDRIVER_EXTENSION  DriverExtension;
  UNICODE_STRING     DriverName;
  PUNICODE_STRING    HardwareDatabase;
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit;
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload;
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
```


- ## Device Object
	- device object is the representation of the actual device presented in the memory
	- Without a Device object, kernel-mode driver will not receive any I/O requests, must be a target device for every I/O request dispatched by I/O Manager.
	- #### IoCreateDevice()
	- - I/O Manager initializes the `DriverObject` field to refer to the driver object that invoked `IoCreateDevice()`
	- ***All device objects created by a kernel-mode driver are linked togetgher using NextDevice*** 

```c
typedef struct _DEVICE_OBJECT {
  CSHORT                   Type;
  USHORT                   Size;
  LONG                     ReferenceCount;
  struct _DRIVER_OBJECT    *DriverObject;
  struct _DEVICE_OBJECT    *NextDevice;
  struct _DEVICE_OBJECT    *AttachedDevice;
  struct _IRP              *CurrentIrp;
  PIO_TIMER                Timer;
  ULONG                    Flags;
  ULONG                    Characteristics;
  __volatile PVPB          Vpb;
  PVOID                    DeviceExtension;
  DEVICE_TYPE              DeviceType;
  CCHAR                    StackSize;
  union {
    LIST_ENTRY         ListEntry;
    WAIT_CONTEXT_BLOCK Wcb;
  } Queue;
  ULONG                    AlignmentRequirement;
  KDEVICE_QUEUE            DeviceQueue;
  KDPC                     Dpc;
  ULONG                    ActiveThreadCount;
  PSECURITY_DESCRIPTOR     SecurityDescriptor;
  KEVENT                   DeviceLock;
  USHORT                   SectorSize;
  USHORT                   Spare1;
  struct _DEVOBJ_EXTENSION *DeviceObjectExtension;
  PVOID                    Reserved;
} DEVICE_OBJECT, *PDEVICE_OBJECT;
```



- ## I/O Request Packets (IRP)
	- The size of IRP depends on the number of stack location that are required for the IRP
	- Kernel-mode components besides I/O manager can use the `IoAllocateIrp` to request a new IRP struct.

```c
typedef struct _IRP {
  CSHORT                    Type;
  USHORT                    Size;
  PMDL                      MdlAddress;
  ULONG                     Flags;
  union {
    struct _IRP     *MasterIrp;
    __volatile LONG IrpCount;
    PVOID           SystemBuffer;
  } AssociatedIrp;
  LIST_ENTRY                ThreadListEntry;
  IO_STATUS_BLOCK           IoStatus;
  KPROCESSOR_MODE           RequestorMode;
  BOOLEAN                   PendingReturned;
  CHAR                      StackCount;
  CHAR                      CurrentLocation;
  BOOLEAN                   Cancel;
  KIRQL                     CancelIrql;
  CCHAR                     ApcEnvironment;
  UCHAR                     AllocationFlags;
  union {
    PIO_STATUS_BLOCK UserIosb;
    PVOID            IoRingContext;
  };
  PKEVENT                   UserEvent;
  union {
    struct {
      union {
        PIO_APC_ROUTINE UserApcRoutine;
        PVOID           IssuingProcess;
      };
      union {
        PVOID                 UserApcContext;
#if ...
        _IORING_OBJECT        *IoRing;
#else
        struct _IORING_OBJECT *IoRing;
#endif
      };
    } AsynchronousParameters;
    LARGE_INTEGER AllocationSize;
  } Overlay;
  __volatile PDRIVER_CANCEL CancelRoutine;
  PVOID                     UserBuffer;
  union {
    struct {
      union {
        KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
        struct {
          PVOID DriverContext[4];
        };
      };
      PETHREAD     Thread;
      PCHAR        AuxiliaryBuffer;
      struct {
        LIST_ENTRY ListEntry;
        union {
          struct _IO_STACK_LOCATION *CurrentStackLocation;
          ULONG                     PacketType;
        };
      };
      PFILE_OBJECT OriginalFileObject;
    } Overlay;
    KAPC  Apc;
    PVOID CompletionKey;
  } Tail;
} IRP;
```



- ## IRP Structgure
	- ### IRP Header
		- MdlAddress
		- AssociatedIrp - A struct contains MasterIRP. created by a higher-level kernel mode driver (filter driver)
		- ThreadListEntry - Before Invoking a Driver dispatch routine via `IoCallDriver()`, all I/O manager routines insert the IRP into a linked  list of IRPs for the **thread**
		- I/O status
		- RequestorMode
		- PendingReturned - Each IRP is typically handled by more than one driver. 
				- Mark IRP `IoMarkIrpPending()`
				- Queue IRP internally
				- Return status code of `STATUS_PENDING`.
				- Process the IRP and pass to next driver
				- Last driver calls `IoCompleteRequest()`
		- Cancel
		- ***ApcEnvironment*** - When IRP is completed, the I/O manager perfroms ***postprocessing*** on tghe IRP in the context of the thread that originally requiested the I/O operation (user-mode process)
		- Zoned
		- Caller-Supplied Arguments - `UserIosb` , `UserEvent`, `UserApcRoutine`. The I/O manager will signal the event upon completion of IRP, upon the Async I/O operation is completed, the caller thread can specify an APC to be invoked upon completion of the IRP. The I/O Manager stores the calling-thread-supplied APC **function pointer** in the `UserAPCRoutine` field
	- ### I/O Stack Location(s)
			
		-  NOTE:  The number of stack locations allocated for an IRP depends on `StackSize` each attached device incremented it byu 1 - one for initial device driver and one for every filter driver..
		- `CurrentStackLocation` is inited in the IRP header with `StackCount + 1` - which points to an invalid stack location pointer value. to dispatch an IRP to the next driver, kernel component must always get a pointer to the next stack location and then fill in the appropriate parameters for the request . When the IRP is dispatched, the next stack lcoation will be `CurrentStackLocation - 1` .
			- The actual current stack location is in `tail.Overlay.CurrentStackLocation`
		![](/assets/images/03-04-20242024-02-19-NT%20Filesystem%20Internals%20Study%20Notes-2.png)
```c
typedef struct _IO_STACK_LOCATION {
  UCHAR                  MajorFunction;
  UCHAR                  MinorFunction;
  UCHAR                  Flags;
  UCHAR                  Control;
  union {
    struct {
      PIO_SECURITY_CONTEXT     SecurityContext;
      ULONG                    Options;
      USHORT POINTER_ALIGNMENT FileAttributes;
      USHORT                   ShareAccess;
      ULONG POINTER_ALIGNMENT  EaLength;
    } Create;
    struct {
      PIO_SECURITY_CONTEXT          SecurityContext;
      ULONG                         Options;
      USHORT POINTER_ALIGNMENT      Reserved;
      USHORT                        ShareAccess;
      PNAMED_PIPE_CREATE_PARAMETERS Parameters;
    } CreatePipe;
    struct {
      PIO_SECURITY_CONTEXT        SecurityContext;
      ULONG                       Options;
      USHORT POINTER_ALIGNMENT    Reserved;
      USHORT                      ShareAccess;
      PMAILSLOT_CREATE_PARAMETERS Parameters;
    } CreateMailslot;
    struct {
      ULONG                   Length;
      ULONG POINTER_ALIGNMENT Key;
      ULONG                   Flags;
      LARGE_INTEGER           ByteOffset;
    } Read;
    struct {
      ULONG                   Length;
      ULONG POINTER_ALIGNMENT Key;
      ULONG                   Flags;
      LARGE_INTEGER           ByteOffset;
    } Write;
    struct {
      ULONG                   Length;
      PUNICODE_STRING         FileName;
      FILE_INFORMATION_CLASS  FileInformationClass;
      ULONG POINTER_ALIGNMENT FileIndex;
    } QueryDirectory;
    struct {
      ULONG                   Length;
      ULONG POINTER_ALIGNMENT CompletionFilter;
    } NotifyDirectory;
    struct {
      ULONG                                                Length;
      ULONG POINTER_ALIGNMENT                              CompletionFilter;
      DIRECTORY_NOTIFY_INFORMATION_CLASS POINTER_ALIGNMENT DirectoryNotifyInformationClass;
    } NotifyDirectoryEx;
    struct {
      ULONG                                    Length;
      FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
    } QueryFile;
    struct {
      ULONG                                    Length;
      FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
      PFILE_OBJECT                             FileObject;
      union {
        struct {
          BOOLEAN ReplaceIfExists;
          BOOLEAN AdvanceOnly;
        };
        ULONG  ClusterCount;
        HANDLE DeleteHandle;
      };
    } SetFile;
    struct {
      ULONG                   Length;
      PVOID                   EaList;
      ULONG                   EaListLength;
      ULONG POINTER_ALIGNMENT EaIndex;
    } QueryEa;
    struct {
      ULONG Length;
    } SetEa;
    struct {
      ULONG                                  Length;
      FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
    } QueryVolume;
    struct {
      ULONG                                  Length;
      FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
    } SetVolume;
    struct {
      ULONG                   OutputBufferLength;
      ULONG POINTER_ALIGNMENT InputBufferLength;
      ULONG POINTER_ALIGNMENT FsControlCode;
      PVOID                   Type3InputBuffer;
    } FileSystemControl;
    struct {
      PLARGE_INTEGER          Length;
      ULONG POINTER_ALIGNMENT Key;
      LARGE_INTEGER           ByteOffset;
    } LockControl;
    struct {
      ULONG                   OutputBufferLength;
      ULONG POINTER_ALIGNMENT InputBufferLength;
      ULONG POINTER_ALIGNMENT IoControlCode;
      PVOID                   Type3InputBuffer;
    } DeviceIoControl;
    struct {
      SECURITY_INFORMATION    SecurityInformation;
      ULONG POINTER_ALIGNMENT Length;
    } QuerySecurity;
    struct {
      SECURITY_INFORMATION SecurityInformation;
      PSECURITY_DESCRIPTOR SecurityDescriptor;
    } SetSecurity;
    struct {
      PVPB           Vpb;
      PDEVICE_OBJECT DeviceObject;
      ULONG          OutputBufferLength;
    } MountVolume;
    struct {
      PVPB           Vpb;
      PDEVICE_OBJECT DeviceObject;
    } VerifyVolume;
    struct {
      struct _SCSI_REQUEST_BLOCK *Srb;
    } Scsi;
    struct {
      ULONG                       Length;
      PSID                        StartSid;
      PFILE_GET_QUOTA_INFORMATION SidList;
      ULONG                       SidListLength;
    } QueryQuota;
    struct {
      ULONG Length;
    } SetQuota;
    struct {
      DEVICE_RELATION_TYPE Type;
    } QueryDeviceRelations;
    struct {
      const GUID *InterfaceType;
      USHORT     Size;
      USHORT     Version;
      PINTERFACE Interface;
      PVOID      InterfaceSpecificData;
    } QueryInterface;
    struct {
      PDEVICE_CAPABILITIES Capabilities;
    } DeviceCapabilities;
    struct {
      PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
    } FilterResourceRequirements;
    struct {
      ULONG                   WhichSpace;
      PVOID                   Buffer;
      ULONG                   Offset;
      ULONG POINTER_ALIGNMENT Length;
    } ReadWriteConfig;
    struct {
      BOOLEAN Lock;
    } SetLock;
    struct {
      BUS_QUERY_ID_TYPE IdType;
    } QueryId;
    struct {
      DEVICE_TEXT_TYPE       DeviceTextType;
      LCID POINTER_ALIGNMENT LocaleId;
    } QueryDeviceText;
    struct {
      BOOLEAN                                          InPath;
      BOOLEAN                                          Reserved[3];
      DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
    } UsageNotification;
    struct {
      SYSTEM_POWER_STATE PowerState;
    } WaitWake;
    struct {
      PPOWER_SEQUENCE PowerSequence;
    } PowerSequence;
#if ...
    struct {
      union {
        ULONG                      SystemContext;
        SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext;
      };
      POWER_STATE_TYPE POINTER_ALIGNMENT Type;
      POWER_STATE POINTER_ALIGNMENT      State;
      POWER_ACTION POINTER_ALIGNMENT     ShutdownType;
    } Power;
#else
    struct {
      ULONG                              SystemContext;
      POWER_STATE_TYPE POINTER_ALIGNMENT Type;
      POWER_STATE POINTER_ALIGNMENT      State;
      POWER_ACTION POINTER_ALIGNMENT     ShutdownType;
    } Power;
#endif
    struct {
      PCM_RESOURCE_LIST AllocatedResources;
      PCM_RESOURCE_LIST AllocatedResourcesTranslated;
    } StartDevice;
    struct {
      ULONG_PTR ProviderId;
      PVOID     DataPath;
      ULONG     BufferSize;
      PVOID     Buffer;
    } WMI;
    struct {
      PVOID Argument1;
      PVOID Argument2;
      PVOID Argument3;
      PVOID Argument4;
    } Others;
  } Parameters;
  PDEVICE_OBJECT         DeviceObject;
  PFILE_OBJECT           FileObject;
  PIO_COMPLETION_ROUTINE CompletionRoutine;
  PVOID                  Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
```


## Processing an IRP

[MSDN Queuing and Dequeuing IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/queuing-and-dequeuing-irps)

- ### On Low-Level Drivers
	- I/O Manager calls to a driver's dispatch routine first
	- `IoStartPacket` routine is called by the driver's dispatch routines
	- The `IoStartPacket()` routine adds the IRP to the device's system-supplied device queue or, if the queue is empty, immediately calls the driver's StartIo routine to process the IRP.
	- Obtains a pointer to current stack location
	- process IRP 
	- completes the I/O request packet
![](/assets/images/03-04-20242024-02-19-NT%20Filesystem%20Internals%20Study%20Notes-3.png)

- ### On High-Level Drivers
	- Not common to have a `StartIo` routine, usually self-contained internal `Queuing and Dequeuing routine`. 
	- If it does, similar to low-level driver described above
