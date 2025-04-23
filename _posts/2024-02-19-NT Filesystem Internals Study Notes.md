---
layout: post
title: NT Filesystem Internals Study Notes
date: 2024-03-04
categories: [Notes, NT FileSystem]
tags:
  - notes
---

# Notes 

- [ChatGPT Answering How Windows Parses Different Path Strings](https://chatgpt.com/share/680839d1-c3c8-8011-b743-66ccc71744fd)

# Special Windows Path Formats and Their Behaviors

## Standard Drive Letter Paths (DOS Paths)

- **Syntax:** The classic DOS/Windows path uses a drive letter and colon, followed by backslashes separating directories, e.g. `C:\Folder\file.txt`. It can be absolute (starting from a drive’s root, like `C:\...`) or relative. A path like `C:Folder\file.txt` (no backslash after the colon) is relative to the current directory on drive C: ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=Important)). Paths that start with a backslash but no drive (e.g. `\Windows\System32`) are relative to the root of the **current** drive ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=drive%20%60C%3A%60.%20%60,relative%20path%20from%20the%20current)).

- **Usage:** Used for local file system access on a specific volume. The drive letter is a *mount point* for a volume. For example, `C:\` typically refers to the volume where Windows is installed. These paths are the most common way users and applications refer to files and directories on local disks.


- **Parsing:** The Windows API will interpret a drive-letter path and translate it to the native NT object path. For instance, `C:\Windows\System32` is converted internally to an NT namespace path like `\??\C:\Windows\System32` ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=environment%20variable%20is%20set%20to,%60%5C%3F%3F%5CC%3A%5CWindows)), where `\??\C:` is a symbolic link to the actual device object (e.g. `\Device\HarddiskVolumeX`) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=A%20DOS%20drive%20such%20as,point%20manager%20implements%20persistence)). If the path is relative (e.g. `C:Folder`), the system uses the current working directory on that drive to resolve it ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=Note%20the%20difference%20between%20the,that%20involve%20Windows%20file%20paths)). Special components `.` and `..` are resolved during this normalization, and forward slashes are replaced with backslashes.

- **Limitations & Special Behaviors:** Traditionally, Windows limited paths to `MAX_PATH` (260 characters) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Maximum%20Path%20Length%20Limitation)). Without special prefixes (discussed below), file APIs will not open paths longer than this limit. Also, certain file names are *reserved* device names, like `NUL`, `CON`, `COM1`, etc. If such a name appears as the final path component (even with an extension), the system treats it as a device. For example, `C:\Windows\NUL.txt` actually refers to the `NUL` device, not a file ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=,%60%5C%3F%3F%5CC%3A%5CWindows)). Using these names in normal paths is blocked to prevent confusion. Drive letter assignments can change between reboots or when adding/removing drives, so a drive letter is not a stable identifier for a volume ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=A%20DOS%20drive%20such%20as,with%20a%20volume%20GUID%20name)) (the system uses volume GUIDs for stable identification, described later).

## UNC Paths (Network Paths)

- **Syntax:** A UNC (Universal Naming Convention) path references network shares using the format `\\ServerName\ShareName\Path\To\File`. It always begins with two backslashes. For example: `\\MyServer\SharedDocs\Report.pdf` refers to the file *Report.pdf* on the share *SharedDocs* on the machine *MyServer*. UNC paths have no drive letter; the `ServerName\ShareName` portion acts like the “volume” name.

- **Usage:** UNC paths are used to access files on remote computers (file servers) over a network. The `ServerName` can be a hostname or IP address, and `ShareName` is a shared folder (as configured on the server). For instance, `\\SERVER\Users\Alice\file.txt` would access a file on a remote server. This is typically used via SMB/CIFS (Windows file sharing) or other network file systems. UNC is also used for special shares like administrative shares (e.g. `\\localhost\C$` for the C: drive).

- **Parsing:** When a Windows file API sees a path starting with `\\`, it recognizes it as a UNC path and will not apply a drive current directory. The path is parsed into a network location request. Internally, the runtime library will transform a UNC path into an NT object path under the `UNC` device. For example, `\\Server\Share\Folder\File` becomes `\??\UNC\Server\Share\Folder\File` in the NT namespace ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=UNC%20paths%20are%20also%20unsurprising,redirector%20for%20an%20SMB%20share)). In the kernel, `\??\UNC` is a symlink to the *Multiple UNC Provider* (`\Device\Mup`) which hands off the request to the appropriate network redirector (e.g. the SMB redirector for an SMB share) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=%60,redirector%20for%20an%20SMB%20share)). The `Server\Share` portion is treated as the network volume; you cannot use “..” to navigate above the share root.

- **Limitations & Special Behaviors:** UNC paths must be fully qualified (they cannot be relative). They require the network redirector to be running and access to the target server. Path length for UNC is also subject to the `MAX_PATH` limit unless the extended syntax (`\\?\UNC\...`) is used (see below). Also, UNC paths may not be accepted by programs that aren’t network-aware or by certain shell interfaces. Permissions and access depend on network credentials. (For named pipes and mailslots, which also use a `\\Server\...` syntax with special “shares” like `pipe` or `mailslot`, see further below.)

## Extended-Length Paths (Verbatim `\\?\` Prefix)

- **Syntax:** An extended-length or *verbatim* path uses the special prefix `\\?\` (literally `\\\\?\\` in a string) before a fully-qualified path. For example: `\\?\C:\Very\Long\Path\file.txt`. For UNC network locations, the format is `\\?\UNC\Server\Share\Folder\file.txt` ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=There%20is%20a%20specific%20link,For%20example)) ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=%60)). You can also use this with volume GUIDs or other device paths (e.g. `\\?\Volume{GUID}\dir\file`). The key is that `\\?\` tells Windows to treat everything following it as a literal path.

- **Purpose/Usage:** The `\\?\` prefix instructs the Win32 API to **disable path parsing & normalization** for the string that follows ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=For%20file%20I%2FO%2C%20the%20,enforced%20by%20the%20Windows%20APIs)). This allows paths longer than 260 characters, and allows otherwise reserved characters or file names. It’s typically used to work with very deep or long paths, or to create files/directories with names that include reserved sequences (like trailing spaces or dots) that are normally stripped. In short, `\\?\` gives applications access to the full capabilities of the file system’s naming, bypassing legacy DOS limitations.

- **How it’s Parsed:** When a path begins with `\\?\`, the Windows API recognizes it and skips the usual normalization (such as resolving `.` and `..`, converting forward slashes, removing trailing dots/spaces) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=difference%20between%20the%20two%20Win32,path%20gets%20normalized)). The prefix is removed and replaced with the NT namespace prefix `\??\` before passing to the kernel ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=The%20straight,path%20gets%20normalized)). Essentially, `\\?\C:\Path\...` becomes `\??\C:\Path\...` internally, which the Object Manager then resolves to the device. Because no normalization is done, the path is taken verbatim – meaning the exact casing, spacing, and length are preserved. It also means the path must be fully qualified (no relative segments allowed) ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=DOS%20device%20paths%20are%20fully,never%20enter%20into%20their%20usage)).

- **Limitations & Requirements:** To use `\\?\` paths, you generally must call Unicode (W) versions of file APIs – ANSI versions may not support long paths properly ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Note%20that%20Unicode%20APIs%20should,you%20to%20exceed%20the%20MAX_PATH)). Historically, only certain APIs respected this prefix, but on modern Windows many do (if long path support is enabled). Starting with Windows 10 (v1607) and newer, the system can be configured to allow long paths without the prefix (with a registry or group policy setting) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=In%20editions%20of%20Windows%20before,Length%20Limitation%20for%20full%20details)), but many applications still use `\\?\` for compatibility. Keep in mind that with `\\?\`, the path **must** be absolute and fully qualified (you can’t start it with `\\?\` and then `..` somewhere). Also, using forward slashes in the path will break the `\\?\` mechanism unless they are converted to backslashes (the prefix only works with the exact `\\?\` sequence) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=difference%20between%20the%20two%20Win32,path%20gets%20normalized)). 

## Win32 Device Paths (`\\.\` Prefix)

- **Syntax:** The `\\.\` prefix (spoken “\\\\ dot \\”) indicates a path to the **Win32 device namespace** rather than the file system. It’s followed by a device identifier. Examples include `\\.\PhysicalDrive0` (the first physical disk) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Another%20example%20of%20using%20the,to%20be%20the%20file%20system)), `\\.\CdRom1` (the second CD/DVD drive), `\\.\COM56` (COM port number 56) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=have%20a%20100%20port%20serial,to%20locate%20a%20predefined%20alias)), or even `\\.\C:` (the volume corresponding to C drive). Named pipe and mailslot paths also use this prefix (e.g. `\\.\pipe\Name`), as do volume GUID paths in one form. Essentially, `\\.\DeviceName` opens a handle to a device or volume instead of an ordinary file. 

- **Purpose/Usage:** This format is used to access devices and volumes directly, bypassing the normal file system path interpretation ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Win32%20Device%20Namespaces)). For example, to open a raw disk for reading/writing, you use `\\.\PhysicalDriveX`. To open a volume (e.g., to read its filesystem boot sector or perform volume-level operations), you can use `\\.\C:` or `\\.\Volume{GUID}`. Serial and parallel ports can be opened as files via names like `\\.\COM1` or `\\.\LPT1`. In general, any driver that creates a named device object accessible to user mode can be opened with a `\\.\` path. This is how **CreateFile** can be used for both file I/O and device I/O ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=For%20example%2C%20if%20you%20want,to%20locate%20a%20predefined%20alias)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Another%20example%20of%20using%20the,to%20be%20the%20file%20system)).

- **Parsing/How it Works:** A path with `\\.\` is recognized by the OS as a *device path*. The `\\.\` is replaced with the NT namespace prefix `\??\` (similar to `\\?\` case) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=The%20straight,path%20gets%20normalized)), so for example `\\.\PhysicalDrive0` becomes `\??\PhysicalDrive0`. Under the hood, the Object Manager looks in the **Global??** directory (global DOS device directory) for the name. Device drivers usually create symbolic links in `\GLOBAL??` for user-friendly names ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)). For instance, the driver for the first hard disk creates a symlink `\GLOBAL??\PhysicalDrive0` that points to `\Device\Harddisk0\DR0` (the device object for that disk) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)). Similarly, `C:` under `\GLOBAL??` is a symlink to `\Device\HarddiskVolume1` (or whatever volume backs drive C) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)). So, opening `\\.\PhysicalDrive0` gives you a handle to the raw disk device, and `\\.\C:` gives a handle to the volume device. In short, `\\.\` paths are routed to the Object Manager’s device namespace, not through the file system parser.

- **Limitations & Special Cases:** Not all APIs accept `\\.\` paths – primarily **CreateFile** (and a few related APIs) are used for device paths ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=If%20you%27re%20working%20with%20Windows,devices%20only%20and%20not%20files)). Most high-level file APIs (and the Windows shell) expect file system paths and will reject or mishandle `\\.\` prefixes ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=If%20you%27re%20working%20with%20Windows,devices%20only%20and%20not%20files)). Typically, you **should not use** `\\.\` for normal files ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=If%20you%27re%20working%20with%20Windows,devices%20only%20and%20not%20files)). Security: opening devices often requires elevated privileges or specific access rights (for example, raw disk access requires Administrator rights). There are also reserved device names inherited from DOS: e.g., `COM1` through `COM9` and `LPT1` etc. The system reserves those so that an app can open “COM1” without the prefix. For device names beyond those (like COM56 in the example), you **must** use `\\.\` since there’s no automatic alias. Another nuance: if you open a volume by drive letter with `\\.\C:`, you should include a trailing backslash (``\\.\C:\``) when calling CreateFile to clearly indicate it’s the volume (some documentation suggests this, though `\\.\C:` often works as well). Also, when accessing a volume or disk directly, you bypass the file system – reading/writing raw bytes. This should be done with care to avoid corruption. 

## Volume GUID Paths (Volume Unique ID)

- **Syntax:** A volume GUID path uses a special **volume identifier** instead of a drive letter. It always appears with the extended-length prefix. The format is: `\\?\Volume{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\` (a GUID in braces, followed by a backslash). For example: `\\?\Volume{b75e2c83-0000-0000-0000-602f00000000}\Windows\System32\kernel32.dll` ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=volume%20by%20using%20its%20volume,This%20takes%20the%20form)). The GUID is a 128-bit unique identifier for the volume.

- **Purpose:** The operating system assigns a GUID to each volume. Unlike drive letters, these **volume GUIDs** are persistent and unique, so they can identify a volume even if drive letters change or if the volume has no drive letter at all ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=Several%20factors%20can%20make%20it,and%20removed%20from%20the%20computer)) ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=To%20solve%20this%20problem%2C%20the,are%20strings%20of%20this%20form)). Volume GUID paths allow you to access a volume by this stable ID. This is useful in scenarios with many volumes or external drives, where drive letters are not reliable. Also, some system volumes (like the EFI partition or recovery partitions) might not have a drive letter, so the only way to reference them from user mode is via the volume GUID path.

- **Parsing:** A volume GUID path must be used with the `\\?\` prefix ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=The%20,Naming%20a%20File%20or%20Directory)), because the raw GUID name is not a normal DOS path component. The `\\?\Volume{GUID}\` prefix is recognized and passed through to the Object Manager as `\??\Volume{GUID}\` ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=The%20straight,path%20gets%20normalized)). In the global DOS devices directory, `Volume{GUID}` entries are symbolic links created by the Mount Manager for each volume ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=%60%5CDevice%5CHarddiskVolume10%5CTemp%60.%20The%20mount,IO_REPARSE_TAG_MOUNT_POINT)). These links point to the actual device, e.g. `\Device\HarddiskVolumeXX`. So, when you open a path like `\\?\Volume{...}\Folder\File.txt`, the system resolves `Volume{...}` to the corresponding device and then opens `\Folder\File.txt` on that volume’s file system. It acts like a “virtual drive” representing that volume.

- **Limitations & Notes:** You must include the trailing backslash after the GUID if you intend to open the volume itself. For example, `\\?\Volume{GUID}\` (with backslash) opens a handle to the root of the volume (similar to a drive like `C:\`). Without the backslash, the path would not be a valid volume device path. When using a volume GUID path, the rest of the path (directories\file) must be absolute on that volume (you cannot have relative paths – by definition the GUID path is fully qualified). Also, volume GUID paths inherently use the extended-length prefix, so they bypass the `MAX_PATH` limit ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=The%20,Naming%20a%20File%20or%20Directory)). They require Windows 2000 or later (that’s when volume GUIDs were introduced along with NTFS mount points). To find the GUIDs for volumes, one can use the `mountvol` command or Win32 APIs. A volume can actually have multiple GUID aliases (the system might generate new GUIDs in some cases or if a volume is mounted in multiple ways) ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=A%20volume%20GUID%20path%20is,than%20one%20volume%20GUID%20path)), but any of them can be used to access the volume.

## NT Namespace (Native Object Paths)

- **Syntax:** Native NT paths refer directly to the Windows object manager namespace. They typically start with a single backslash (`\`) which denotes the root of the NT object hierarchy, followed by names of directories/objects. For example: `\Device\HarddiskVolume2\Windows\System32\kernel32.dll` or `\??\C:\Windows\System32\kernel32.dll`. These are **not** usually seen by end-users, but they are the form that Win32 paths ultimately translate into.

- **Purpose:** The NT namespace is the fundamental naming system in the OS kernel, where all devices, volumes, files, and objects reside. Most user-land code doesn’t use native paths directly, but some lower-level APIs (NT Native APIs, or certain Windows drivers and tools) can work with them. Using NT paths can be a way to bypass the Win32 subsystem’s path processing. For example, a kernel-mode component or a very low-level tool might open `\Device\HarddiskVolume1\EFI\Boot\bootx64.efi` to access a file on a volume without referring to drive letters. In user mode, typical Win32 file APIs do not accept native paths *unless* you use the special prefixes (`\\?\` or `\\?\GLOBALROOT\`).

- **Parsing/Behavior:** In the kernel, the **Object Manager** interprets paths starting at `\`. For instance, `\Device\HarddiskVolume2\...` goes to an actual device object in the `\Device` directory. `\??\` is a special directory in the object namespace (actually `\??` is the same as `\GLOBAL??` in modern Windows) that holds the DOS device symlinks (like drive letters and `PhysicalDrive0`) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=is%20useful%20to%20browse%20the,a%20disk%2C%20and%20so%20on)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)). The Win32 subsystem automatically maps drive-letter paths to the `\??` namespace. Normally, user applications don’t need to specify `\Device` paths because the system does the mapping. However, if an API allows a *“NT namespace path”*, you could specify the full object path (e.g. NtOpenFile might take `\Device\HarddiskVolume2\file`). There is also a special Win32 prefix `\\?\GLOBALROOT\` which lets a user-mode caller break out to the true NT root namespace ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=With%20the%20addition%20of%20multi,dependent%20path)). For example, `\\?\GLOBALROOT\Device\HarddiskVolume2\Windows\System32` would be interpreted as an NT path to that directory, bypassing the normal `\??` (DOS devices) resolution and any per-session device mappings. `GLOBALROOT` is essentially a symlink that points to `\` (the root of the object namespace) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=With%20the%20addition%20of%20multi,dependent%20path)).

- **Limitations & Special Cases:** Using native paths is advanced and typically only done in system-level code. The `\\?\GLOBALROOT\` trick is one of the few ways to use a native path via the Win32 file APIs, primarily for special cases (like accessing global devices from a restricted context, or when a device name might conflict with a DOS device name in a session). Most Win32 programs cannot parse NT object paths (e.g., a path starting with `\Device\` will confuse standard file dialogs or .NET APIs unless `\\?\GLOBALROOT\` is used). Also, a native path must be fully qualified from the root (`\`); there’s no concept of a “current directory” for native paths. In practice, you’ll seldom use this format unless you’re debugging or dealing with very low-level operations. The OS provides the higher-level namespaces (Win32 file namespace and Win32 device namespace) so that normal programs never have to deal with raw object manager paths ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=NT%20Namespaces)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)).

## Named Pipe Paths (IPC via `\pipe\`)

- **Syntax:** Named pipe paths use a UNC-like syntax with the keyword `pipe`. The format is `\\ServerName\pipe\PipeName`. For example, `\\.\pipe\MyPipe` refers to a named pipe called "MyPipe" on the local machine (since `.` means local) ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=)). Similarly, `\\Server01\pipe\MyPipe` would refer to the pipe "MyPipe" on a remote machine named *Server01*. The `pipe` part is literal – it indicates the path is targeting the Named Pipe file system.

- **Purpose:** Named pipes provide inter-process communication (IPC), either between processes on the same computer or over the network between processes on different computers. The path format is designed to look like a network path so that the same API (CreateFile, etc.) can be used to open them. For local pipes, the server creates `\\.\pipe\Name` and clients use the same path to connect. For remote pipes, the server must be running the “Server” service (which allows pipe access via SMB), and clients specify the server’s name.

- **Parsing & Interpretation:** When a path beginning with `\\Something\pipe\...` is used in CreateFile/WaitNamedPipe, Windows knows this is a pipe path (because the segment after the server is exactly "pipe"). Locally, `\\.\pipe\PipeName` is translated by the OS to access the **Named Pipe Filesystem (NPFS)** driver. In the NT object namespace, there is a device `\Device\NamedPipe` and a corresponding entry under `\??\pipe` or similar for user-mode. Essentially, the `pipe\PipeName` part goes into the pipe namespace, and the pipe is identified by that name. For remote pipes (`\\Server\pipe\Name`), the request is handed to the network redirector (just like a UNC path, it goes via `\??\UNC\Server\pipe\Name`) but the server’s SMB service will recognize it as a pipe request and route it to its NPFS. In effect, `\\Server\pipe\Name` uses SMB protocol to talk to the `\Device\NamedPipe` on the remote server. 

- **Limitations & Special Behaviors:** The pipe name portion can be up to 256 characters and can include any characters except backslash (since backslash delimits subpath) ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=where%20ServerName%20is%20either%20the,sensitive)). Pipe names are case-insensitive. Only processes with the right permissions (and running under accounts allowed by the pipe’s security) can connect. One cannot navigate a pipe path like a file system (there’s no concept of subdirectories under `pipe`). Also, while the syntax resembles UNC, you cannot use `\\?\` extended prefix for pipe paths – the pipe API is separate. The `"\\.\pipe"` prefix is accepted only by certain functions (CreateFile, etc.), not by general file utilities. Example: a server creates a pipe by calling `CreateNamedPipe("\\\\.\\pipe\\MyPipe", ...)`, and a client connects with `CreateFile("\\\\.\\pipe\\MyPipe", ...)` ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=Use%20the%20following%20form%20when,7%2C%20or%20CallNamedPipe%20function)) ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=)). If the client is on another machine, they would use `\\\\ServerName\\pipe\\MyPipe` as the path. Named pipes do not store data in the file system; reading/writing to them passes data between processes (or across the network).

## Mailslot Paths (One-way IPC)

- **Syntax:** Mailslot naming also uses a UNC-style path with the keyword `mailslot`. For a local mailslot, the path is `\\.\mailslot\<SlotName>`. For example, `\\.\mailslot\SampleSlot`. A remote mailslot (to send a message to another machine) would be `\\HostName\mailslot\SlotName`. Wildcards like `*` can be used in place of the host to broadcast to all listeners in a domain or network segment (e.g. `\\* \mailslot\SlotName` to broadcast) – this was used by certain services for one-to-many messaging.

- **Purpose:** Mailslots are a legacy IPC mechanism for one-way messages. A process (the server) creates a mailslot to receive messages, and other processes (clients) send messages by writing to that mailslot path. It was often used for simple broadcasts or notifications (for example, the old WinNT “Messenger” service for `NET SEND` used a mailslot). Mailslots can deliver messages locally or across a network (via datagram over SMB/NetBIOS) ([The beginning of the end of Remote Mailslots as part of Windows Insider | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/filecab/the-beginning-of-the-end-of-remote-mailslots-as-part-of-windows-insider/3762048#:~:text=The%20Remote%20Mailslot%20protocol%20is,for%20instance)).

- **Parsing & How it Works:** When `CreateMailslot` is called with a name like `\\.\mailslot\Name`, the system creates a mailslot object in the local mailslot filesystem (the driver that handles mailslots). The path `\\.\mailslot\Name` is essentially a hook for that driver. The `\\.\` indicates the device namespace, and `mailslot\Name` is looked up by the mailslot driver. In code, you’ll see definitions like `LPCTSTR name = "\\\\.\\mailslot\\sample_mailslot"` ([Creating a Mailslot - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/creating-a-mailslot#:~:text=HANDLE%20hSlot%3B%20LPCTSTR%20SlotName%20%3D,mailslot%5C%5Csample_mailslot)). For a client to send to the mailslot, it uses CreateFile on the same path. If a remote computer is specified (e.g. `\\SERVER\mailslot\Name`), the request is sent over the network. Internally, remote mailslot messages were transported via SMB1’s datagram (NetBIOS) service, not the regular file I/O – essentially an SMB transaction with a special mailslot protocol ([The beginning of the end of Remote Mailslots as part of Windows Insider | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/filecab/the-beginning-of-the-end-of-remote-mailslots-as-part-of-windows-insider/3762048#:~:text=method%20learn,for%20instance)). The remote machine’s redirector would hand it to the mailslot on that machine. (Note: Modern Windows are phasing out remote mailslots due to their dependency on the outdated SMB1/NetBIOS protocols ([The beginning of the end of Remote Mailslots as part of Windows Insider | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/filecab/the-beginning-of-the-end-of-remote-mailslots-as-part-of-windows-insider/3762048#:~:text=Windows%2011%20Insider%20Preview%20Build,are%2C%20a%20bit%20more%20information)) ([The beginning of the end of Remote Mailslots as part of Windows Insider | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/filecab/the-beginning-of-the-end-of-remote-mailslots-as-part-of-windows-insider/3762048#:~:text=Common%20Internet%20File%20System%20,for%20instance)).)

- **Limitations & Special Behaviors:** Mailslots are unreliable (no guarantee of delivery) and support only one-way, short messages (typically up to 424 bytes for LAN broadcasts). For local use, they can be an easy way to send simple notifications. The naming is similar to pipes, but mailslot namespace is separate. Only datagram-oriented writing is allowed (you open a mailslot file with CreateFile (GENERIC_WRITE) to send a message). Reading from a mailslot is only done by the owning server via ReadFile on the handle from CreateMailslot. Security for mailslots is limited (they were not designed with robust security, and remote mailslot traffic isn’t authenticated in the way SMB named pipes can be). Additionally, because remote mailslots rely on SMB1, on modern systems that have SMB1 disabled by default, remote mailslot communication will fail unless SMB1 (and the mailslot feature) is explicitly re-enabled ([The beginning of the end of Remote Mailslots as part of Windows Insider | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/filecab/the-beginning-of-the-end-of-remote-mailslots-as-part-of-windows-insider/3762048#:~:text=25314%20blogs,one%20of%20the%20following%20errors)). In summary, mailslot paths are a special-case format for a legacy IPC mechanism; they behave like files for the API, but they aren’t real filesystem paths on disk.

**Sources:**

- Microsoft Docs – *Naming Files, Paths, and Namespaces* (Win32 File I/O reference) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=For%20file%20I%2FO%2C%20the%20,enforced%20by%20the%20Windows%20APIs)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Another%20example%20of%20using%20the,to%20be%20the%20file%20system)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=If%20you%27re%20working%20with%20Windows,devices%20only%20and%20not%20files)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx))  
- Microsoft Docs – *File path formats on Windows* (.NET/Windows IO) ([File path formats on Windows systems - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#:~:text=There%20is%20a%20specific%20link,For%20example)) ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=To%20solve%20this%20problem%2C%20the,are%20strings%20of%20this%20form)) ([Naming a Volume - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume#:~:text=The%20,Naming%20a%20File%20or%20Directory))  
- Microsoft Docs – *Pipe Names* (Named Pipe IPC) ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=))  
- Microsoft Docs – *Named Pipe Client* example ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=)) ([Pipe Names - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names#:~:text=))  
- Microsoft Docs – *Creating a Mailslot* (example code) ([Creating a Mailslot - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/ipc/creating-a-mailslot#:~:text=HANDLE%20hSlot%3B%20LPCTSTR%20SlotName%20%3D,mailslot%5C%5Csample_mailslot))  
- Microsoft Sysinternals – *WinObj* tool and Windows Object Manager namespace info ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=is%20useful%20to%20browse%20the,a%20disk%2C%20and%20so%20on)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=To%20make%20these%20device%20objects,Device%5CXxx)) ([Naming Files, Paths, and Namespaces - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=With%20the%20addition%20of%20multi,dependent%20path))  
- Relevant Q&A (Stack Overflow) on Windows path prefixes and NT namespace ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=The%20straight,path%20gets%20normalized)) ([windows - Path prefixes \??\ and \\?\ - Stack Overflow](https://stackoverflow.com/questions/23041983/path-prefixes-and#:~:text=UNC%20paths%20are%20also%20unsurprising,redirector%20for%20an%20SMB%20share)) (explains `\\?\` vs `\\.\` and internal mappings)

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
