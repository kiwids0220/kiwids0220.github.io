---
layout: post
title: Useful Pwndbg & WinDbg Commands & IDA Pro Scripts
date: 2024-02-11
tags: [notes, Pwndbg, WinDbg, IDA Pro]
categories: [Notes, Debugging, RE]

---
### Windbg to Pwndbg
Thanks to the Pwndbg dev team, users coming from Windbg will find pwndbg quite handy with the `db, dt, dq, dq, etc...` flags in Pwndbg. I really like the `dt` flag that will print out the type given a variable name.
![](/assets/images/2024-01-31-dt.png)

I also like `ptype` command which will print the type of the variable

```
pwndbg> ptype fast_reload_t
type = struct fast_reload_s {
    FastReloadMemoryMode mode;
    shadow_memory_t *shadow_memory_state;
    snapshot_page_blocklist_t *blocklist;
    nyx_fdl_t *fdl_state;
    nyx_dirty_ring_t *dirty_ring_state;
    nyx_fdl_user_t *fdl_user_state;
    nyx_device_state_t *device_state;
    nyx_block_t *block_state;
    _Bool root_snapshot_created;
    _Bool incremental_snapshot_enabled;
    nyx_coverage_bitmap_copy_t *bitmap_copy;
    uint32_t dirty_pages;
}
```

`info locals` is another good one that can list Local variables of the current stack frame.



## Useful Windbg command

### Finding dispatcher object (Event, mutex, etc...)
- Finding the usermode process 
```
!process 0 0 lsass.exe
```
- After finding the process address, list threads info and check those DISPATCHER_OBJECT
```
!process ffff8005bd42c080 6
```
![](/assets/images/2024-01-31-windbgProcessThreadinfo.png)
- Checking the DISPATCHER_OBJECT HEADER 
```
dt nt!_DISPATCHER_HEADER ffff8005b84bd5a0
```

![](/assets/images/2024-01-31-DISPATCHER_OBJECT.png)

### Finding the object with the name
- Given a object name
    ```
    kd> !object \SECURITY\LSA_AUTHENTICATION_INITIALIZED
    Object: ffff8005b84bd5a0  Type: (ffff8005b84c1f00) Event
        ObjectHeader: ffff8005b84bd570 (new version)
        HandleCount: 1  PointerCount: 32770
        Directory Object: ffffcc0a23c1c770  Name: LSA_AUTHENTICATION_INITIALIZED   
    ```
- Highlight the Object address by `Crtl + Left Click` on the address `ffff8005b84bd5a0`

- Search the handle table `!findhandle ffff8005b84bd5a0`
![](/assets/images/2024-01-31-0x614.png)

- Validate the handle
![](/assets/images/2024-01-31-handle.png)
- Directory object
![](/assets/images/2024-01-31-ObjectDirectory.png)


### Checking Nt!_KTHREAD for objects waiting
```
kd> dx -id 0,0,ffff8005bd42c080 -r1 ((ntdll!_KTHREAD *)0xffff8005bd393080)
((ntdll!_KTHREAD *)0xffff8005bd393080)                 : 0xffff8005bd393080 [Type: _KTHREAD *]
	...
    [+0x0c8] WaitStatus       : 0 [Type: __int64]
    [+0x0d0] WaitBlockList    : 0xffff8005bd3931c0 [Type: _KWAIT_BLOCK *]
	...
	
```

```
kd> dt _KWAIT_BLOCK 0xffff8005bd3931c0
ntdll!_KWAIT_BLOCK
   +0x000 WaitListEntry    : _LIST_ENTRY [ 0xffff8005`b84bd5a8 - 0xffff8005`b84bd5a8 ]
   +0x010 WaitType         : 0x1 ''
   +0x011 BlockState       : 0x4 ''
   +0x012 WaitKey          : 0
   +0x014 SpareLong        : 0n671
   +0x018 Thread           : 0xffff8005`bd393080 _KTHREAD - THREAD RUNNING HARNESS
   +0x018 NotificationQueue : 0xffff8005`bd393080 _KQUEUE
   +0x020 Object           : 0xffff8005`b84bd5a0 Void - EVENT Object: LSA_AUTHENTICATION_INITIALIZED
   +0x028 SparePtr         : (null) 

kd> !object 0xffff8005`b84bd5a0
Object: ffff8005b84bd5a0  Type: (ffff8005b84c1f00) Event
    ObjectHeader: ffff8005b84bd570 (new version)
    HandleCount: 1  PointerCount: 32770
    Directory Object: ffffcc0a23c1c770  Name: LSA_AUTHENTICATION_INITIALIZED


```
### Checking NT!_DISPACTHER_HEADER for thread waiting
```
dt -r1 nt!_KEVENT ffff8005b84bd5a0 () Recursive: [ -r1 -r2 -r ] Verbose Normal dt
==================================================================================
   +0x000 Header               : _DISPATCHER_HEADER
      +0x000 Lock                 : 0n33947648 (0x2060000)
      +0x000 LockNV               : 0n33947648 (0x2060000)
      +0x000 Type                 : 0 ''
      +0x001 Signalling           : 0 ''
      +0x002 Size                 : 0x6 ''
      +0x003 Reserved1            : 0x2 ''
      +0x000 TimerType            : 0 ''
      +0x001 TimerControlFlags    : 0 ''
      +0x001 Absolute             : 0y0
      +0x001 Wake                 : 0y0
      +0x001 EncodedTolerableDelay : 0y000000 (0)
      +0x002 Hand                 : 0x6 ''
      +0x003 TimerMiscFlags       : 0x2 ''
      +0x003 Index                : 0y000010 (0x2)
      +0x003 Inserted             : 0y0
      +0x003 Expired              : 0y0
      +0x000 Timer2Type           : 0 ''
      +0x001 Timer2Flags          : 0 ''
      +0x001 Timer2Inserted       : 0y0
      +0x001 Timer2Expiring       : 0y0
      +0x001 Timer2CancelPending  : 0y0
      +0x001 Timer2SetPending     : 0y0
      +0x001 Timer2Running        : 0y0
      +0x001 Timer2Disabled       : 0y0
      +0x001 Timer2ReservedFlags  : 0y00 (0n0)
      +0x002 Timer2ComponentId    : 0x6 ''
      +0x003 Timer2RelativeId     : 0x2 ''
      +0x000 QueueType            : 0 ''
      +0x001 QueueControlFlags    : 0 ''
      +0x001 Abandoned            : 0y0
      +0x001 DisableIncrement     : 0y0
      +0x001 QueueReservedControlFlags : 0y000000 (0)
      +0x002 QueueSize            : 0x6 ''
      +0x003 QueueReserved        : 0x2 ''
      +0x000 ThreadType           : 0 ''
      +0x001 ThreadReserved       : 0 ''
      +0x002 ThreadControlFlags   : 0x6 ''
      +0x002 CycleProfiling       : 0y0
      +0x002 CounterProfiling     : 0y1
      +0x002 GroupScheduling      : 0y1
      +0x002 AffinitySet          : 0y0
      +0x002 Tagged               : 0y0
      +0x002 EnergyProfiling      : 0y0
      +0x002 SchedulerAssist      : 0y0
      +0x002 ThreadReservedControlFlags : 0y0
      +0x003 DebugActive          : 0x2 ''
      +0x003 ActiveDR7            : 0y0
      +0x003 Instrumented         : 0y1
      +0x003 Minimal              : 0y0
      +0x003 Reserved4            : 0y00 (0n0)
      +0x003 AltSyscall           : 0y0
      +0x003 UmsScheduled         : 0y0
      +0x003 UmsPrimary           : 0y0
      +0x000 MutantType           : 0 ''
      +0x001 MutantSize           : 0 ''
      +0x002 DpcActive            : 0x6 ''
      +0x003 MutantReserved       : 0x2 ''
      +0x004 SignalState          : 0n0
      +0x008 WaitListHead         : _LIST_ENTRY [ 0xffff8005`bd3931c0 - 0xffff8005`bd3931c0 ] [EMPTY OR 1 ELEMENT]


kd> dt _KWAIT_BLOCK  0xffff8005`bd3931c0
ntdll!_KWAIT_BLOCK
   +0x000 WaitListEntry    : _LIST_ENTRY [ 0xffff8005`b84bd5a8 - 0xffff8005`b84bd5a8 ]
   +0x010 WaitType         : 0x1 ''
   +0x011 BlockState       : 0x4 ''
   +0x012 WaitKey          : 0
   +0x014 SpareLong        : 0n671
   +0x018 Thread           : 0xffff8005`bd393080 _KTHREAD
   +0x018 NotificationQueue : 0xffff8005`bd393080 _KQUEUE
   +0x020 Object           : 0xffff8005`b84bd5a0 Void
   +0x028 SparePtr         : (null) 
```

### IDA Pro Scripts

#### Collecting all functions called within a function

```py
import ida_funcs
import idautils
import idaapi
import idc

def extract_function_name(name):
    if '@@' in name:
        return name.split('@@')[0]
    return name


def list_function_calls_within(func_ea):
    func = ida_funcs.get_func(func_ea)
    if func is None:
        print(f"No function found at 0x{func_ea:08X}")
        return

    func_name = ida_funcs.get_func_name(idc.here())
    print(f"Function calls within function {func_name} at 0x{func_ea:08X}:")
    for head in idautils.FuncItems(function_address):
        for insn in idautils.XrefsFrom(head, idaapi.XREF_FAR):
            if insn.type == idaapi.fl_CN:
                called_func = ida_funcs.get_func(insn.to)
                if called_func:
                    if "WPP" not in ida_funcs.get_func_name(insn.to):  
                        print(f"0x{insn.to:08X}: {extract_function_name(ida_funcs.get_func_name(insn.to))}")

# Replace 0x12345678 with the address of the function you want to analyze
function_address = idc.here()
list_function_calls_within(function_address)

```
