---
layout: post
title: NT Filesystem Internals Study Notes
date: 2024-03-04
categories: Notes
tags:
  - notes
---
# The Book

![](/assets/images/03-04-20242024-02-19-NT%20Filesystem%20Internals%20Study%20Notes.png)


# Notes 

## Spin Locks

- Spin lock are used to lock shared data to make sure there’s only one thread executed by one processor to access it.

- Dispatcher objects are provided by the kernel to the Executives

Dispatch Obj vs Spin lock:

- Spin lock will keep trying to require the lock, dispatcher object will put the thread to suspended state

Mutex vs Event

-  Event doesn’t provide the mutual exclusiveness between threads executed by processors while Mutex and Spin locks do 


### NT I/O Manager

- Execution Context
	- the kernel driver's code may be executed by many other threads outside of the context of the driver
	- This is important because depending on their context, they might not have access to other resources or have knowledge of.

		- The Context of a user-mode thread that has requested system services : the code will often execute in the context of the user-mode thread that requests any I/O operations (e.x., Read File)

	- The context of the dedicated worker thread created by the drive, or by some kernel-mode component. They can do so by invoking `PsCreateSAystemThread()`.

	- The context of system worker threads specially created by the I/O manager to serve I/O subsystem components. Usually happens in the `Async I/O requests`. from user-mode applications. The request will be picked up and handled by a system worker thread.

