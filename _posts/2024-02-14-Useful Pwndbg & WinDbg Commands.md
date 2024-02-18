---
layout: post
title: Useful Pwndbg & WinDbg Commands
date: 2024-02-11
tags: [Pwndbg, WinDbg]
categories: [Debugging, Pwndbg, WinDbg]
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

#### Finding dispatcher object (Event, mutex, etc...)
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

#### Finding the object with the name
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