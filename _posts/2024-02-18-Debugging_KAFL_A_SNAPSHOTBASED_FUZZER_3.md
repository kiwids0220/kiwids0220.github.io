---
layout: post
title: Debugging kAFL, A Snapshot-based Fuzzer - Part III
date: 2024-02-18
categories: [Virtualization, Nyx, kAFL]
tags: [fuzz]
---

## Debugging the Windows Dump?

This is not your typical dump you collected from a kernel panic crash or from WinDbg. This is the dump we collected via some additional loops in QEMU monitor, in case if you missed it, you can find what I did from my [last post]({{ site.baseurl }}{% post_url 2024-02-13-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_2 %}). Since the dump we had is in WinDbg-compatible format. We can sure leverage WinDbg again to troubleshoot where the "Hang" comes from...

## Dump Analysis Using WinDbg

Well, telling WinDbg to analyze our dump is quite easy, just simply drag and drop the `.dmp` file into WinDbg and run `!analyze -v`.
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3.png)

After the WinDbg finished analyzing, we can find our harness by locating the process Ex.
`!process 0 0 lsass.exe`.  
We may also list information regarding all threads running under our harness process with `!process 0 7 lsass.exe` 
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-1.png)
Right off the bat, we find our thread that's running our harness, however, it is at a wait stage as the WinDbg says:
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-3.png)
A couple of things worth noting: 
- This is a Alertable event that the thread is waiting for. 
- The `NoficationEvent`  - Describe the type of Events. (more on `Event` objects can be found [here](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects) and [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializeevent))

### Please Wait()

We know the thread is waiting for the Event to be  "Signaled" so our thread can continue executing our harness. But what function lead to the `NtWaitForSingleObjet()`. The answer can be found yet again in the screenshot - `Sspi!LsaRegisterLogonProcess()`. [LsaRegisterLogonProcess](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaregisterlogonprocess) is a interesting function and Microsoft documented as
> The **LsaRegisterLogonProcess** function establishes a connection to the LSA server and verifies that the caller is a logon application.

If we open the function in IDA, we will find where the call is made! 
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-4.png)

### Finding the Event in WinDbg

If you want to know how to find this "named" Event object in WinDbg dump, check out [my other note]({{ site.baseurl }}{% post_url 2024-02-14-Useful Pwndbg & WinDbg Commands %}).

We will be utilizing some old MS WinDbg extension called [Mex](https://github.com/DebugPrivilege/InsightEngineering/tree/main/Debugging%20101/Section%201%3A%20Introduction%20to%20MEX), Thanks for the people who made this extension and also  [@DebugPrivilege](https://twitter.com/DebugPrivilege) who documented the usefulness of it.

Once you downloaded Mex and extracted to disk, run `.load PATH_TO_MEX.dll` in your WinDbg console.

After that, we can utilize its `!p` to dump the process information given our `lsass.exe` address. Next, we can list all threads information by just clicking on the `!mex.listthreads`
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-5.png)
We found the same thread that was running our harness, and now let's list more detail about the thread. Look, there's our `Event` we just saw previously in IDA, and the name also matches.
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-6.png)
Now we can further inspect the `Object` by following the link of the address pointing to our `NotificationEvent`. The `WaitBlockList` is a field of `nt!_THREAD` struct which specifies a list of synchronization object that the thread is waiting on, find more info [here](https://codemachine.com/articles/kernel_structures.html).
![](/assets/images/02-18-20242024-02-18-Debugging_KAFL_A_SNAPSHOTBASED_FUZZER_3-7.png)

## kAFL Timeout
Perhaps it was too early for the Event to be set for listening or the thread that's supposed to signal the Event hasn't done so (because of the "hacky" way I injected my harness), our harness thread was "hanging" at this point. Since kAFL is a snapshot-based fuzzer, it utilize `QEMU-Nyx` to achieve **rapid VM reload** at the point where the system snapshot was taken and when the execution ends. kAFL also specifies **soft/hard timeouts** for execution, if harness thread is **blocked/put into a wait state**, and if the **thread was blocked for the duration that's longer than the timeout**, then the **VM will be reset by the fuzzer**. In this case, our `Event` was not signaled which caused our harness thread "hangs" virtually forever and  kAFL resetted the VM, the infinite loop keeps on going...


## Closing 

It was very interesting diving into the fuzzer and troubleshoot our harness problem. This whole journey sparked my interested in Fuzzing, Hypervisor studies and I am excited for the future blog posts! 

Happy lunar new year and see you on the other side!

