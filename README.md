## WindowsD - Fixing broken windows

*Aka drivers won't load, processes are unkillable, registry can't be edited...*

WinD is a 3rd party "jailbreak" so administrators can remove some
mal-features introduced in modern windows versions. Currently, it can disable:

* Driver signing, including WHQL-only locked systems (secureboot tablets).
* Protected processes (used for DRM, "WinTcb").
* Read-only, "invulnerable" registry keys some software and even windows itself employs

WinD works similiarly to [other tools](https://github.com/hfiref0x/DSEFix) which disable DSE, but is
designed to be more user friendly and support for more OS/hardware combinations.

It is also designed to be "transparent", that is anything probing for
"integrity" - typically DRM - will still see the system as locked down,
even if drivers and processes are accessible to system administrator.

The idea is more or less 'run once and forget'.

Only accounts with SeLoadDriverPrivilege (admin) can use it.

### Supported windows versions

Almost all builds of Windows 7, 8.1 and 10, 32bit and 64bit on Intel CPUs were tested.
You need to use specific WinD32/64 .exe according to bit-ness of your system.

XP64, Vista and server editions *may* work, but you're on your own.

### Usage

Download Wind32/64 according to bit edition of windows and simply click the
exe. An installation wizard should start guiding through installation (it
should be enough to answer y to everything). After that, your system should
be unlocked and software with unsigned drivers should start working
normally again.

### Advanced usage

If you don't want to install on-boot loader, but only load particular
service/driver while bypassing DSE, type:

```
> wind64 /l yourdriver.sys
```
\- or -
```
> wind64 /l DriverServiceName
```

But if you want your system to ignore signatures as a whole (ie load installed
drivers at boot), use:

```
> wind64 /i
```

Which will install it as a service permanently. It is recommended you create
a system restore point beforehand, in the event something will not go as planned.

In case you want to uninstall the service (and re-lock your system), use:

```
> wind64 /u
```

### Process protection

Windows has a concept of "protected process" - one which cannot be tampered
with. Of course this is only a fiat restriction, and we can disable it with:

```
> wind64 /d 1234
```

Where 1234 is PID of the process you want to unprotect. Once unprotected,
a debugger can be attached, hooks can be injected etc. This command is
useful only on Win7 and early win8/10 - later versions use patchguard to
watch for changes of protection flags.

Meaning you have to employ same trick as we do for loading drivers - reset
protection, do your stuff, restore protection - and do it quick. This can
be done only via the C API.

Another route is elevate your own process to WinTcb level (which should not
register it with PG), at which point it should be possible to fiddle with
other WinTcb process. For that, you need to get familiar with internal
encodings of PS_PROTECTION structure. More in-depth description can be
found at Alex's blog:

* [Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1](http://www.alex-ionescu.com/?p=97)
* [Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](http://ww.alex-ionescu.com/?p=116)
* [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers)](http://www.alex-ionescu.com/?p=146)

### Registry

Windows contains 3 mechanisms to make dealing with registry especially painful:

1. "Hard R/O lock", an undocumented, but publicly exported system call, `NtLockRegistryKey()`. This will
   make given key read-only, until next reboot. Worse still, there does not need to be even a process or driver
   holding onto the key.
2. "Soft Lock", `NtNotifyChangeKey()`. For this one, there has to be something holding on the open key handle and
   listening to notifications about changes to key value. The listener is either a thread, or kernel-resident
   driver. They'll usually silently replace the key back to value they want. No errors are reported, but the key
   cannot be edited.
3. Global hooks. These can be installed only by kernel drivers, and hook directly to registry operation calls.
   These are not per-key. Originally designed for AV software, but malware has use for it too.

Note that all methods work at run time, they are not permanent permission within the registry.
"Protection" like this, unlike permissions, works only within the currently running session.

WindowsD allows you to override and control all of these methods.

#### Method 1
Parameters `/RD` and `/RE`:

```
> wind64 /RE \Registry\Machine\SYSTEM\CurrentControlSet\Control\Services
```
Will very sternly disallow writing to this subtree - no new services can be installed. There does
not exist permission to disable this setting (except via `/RD` command), and almost nothing can
override it - not even internal kernel APIs.

`/RD` and `/RE` can be issued on any key.

#### Method 2
Parameters `/ND` and `/NE`
```
> wind64 /ND \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Windows
```
Will disable notifications on this subtree (which contains frequently hijacked autorun, `AppInit_DLLs`).
Now you can edit it back to value you want, without something mysterious forcing it back. Finally, you
can even protect it with `/RE`.

Note that `/NE` can be issued only on key with notifications previously disabled via `/ND`

All registry paths are NT, not the usualy Win32 ones:

* `\HKLM\` becomes `\Registry\Machine\`
* `\HKCU\` becomes `\Registry\User\`

#### Method 3

Uses parameters `/CD` and `/CE`. There is no registry path to specify (that is specific
to the driver which registered the callback), so we can simply disable and re-enable again all
hooks present.

### Bugs / BSODs

The tool depends on many undocumented windows internals, as such, may break
every windows update. Usually, it will simply refuse to load and you'll see
all restrictions in effect again. There is a small chance it will render system
unbootable too, so before installing via `wind /i`, USE the system restore.

If you boot your system in safe mode, the driver will refuse to load as well,
and then you can simply uninstall the service via `/U` or manually:

```
> sc delete WinD64inject
```

If you get a BSOD, open an issue with exact version of windows and build number,
and attach the following files from your system: `CI.DLL`, `NTOSKRNL.EXE`

### API

There is header-only C API - `wind.h` Usage goes like:

* `handle = wind_open()` - open the control device, NULL handle on error
* `wind_ioctl(handle,command,buffer,buflen)` - send command(s)
* `wind_close(handle)` - close the control device

`command` can be:

`WIND_IOCTL_INSMOD` - load driver, bypassing DSE. Service entry must already
exist for the driver. Buffer is UTF16 service registry path, length is size of
buffer in bytes, including terminating zeros.

`WIND_IOCTL_PROT` - set/unset process protection. buffer points to `wind_prot_t`
typed buffer.

* `buf->pid` - set to pid you want to change protection flags for.
* `buf->prot` - contents of this struct are copied to process protection flags,
  but original protection flags of process will be returned back in the same
  buffer - ie contents will be swapped.

To unprotect a process, just clear all its flags - bzero(&buf->prot).

You can re-protect a process after you're done with it, simply by calling the
ioctl again with same buffer (it holds the original flags) and the `buf->prot`
will be swapped again.

`WIND_IOCTL_REGNON/OFF, WIND_IOCTL_REGLOCKON/OFF`

These take string with registry key as paramater, and can turn locking and notifications on/off.

### Internals

Just like DSEfix and things similiar to it, we simply load a signed driver,
exploit vulnerability in it to gain access to kernel, and override the
policy with whatever we want. There are some differences too:

* Custom signed driver exploit is used, [technical details here](http://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/#more)
* 32bit support (Win8+ secureboot).
* Can coexist with vmware/vbox as the exploit is not based on those (and hence
  does not need CPU with VT support either).
* The vulnerable driver is WHQL signed, so it works even on systems restricted
  to WHQL via secureboot env.
* We automate `reset ci_Options` -> `load unsigned` -> `ci_Options restore`
  PatchGuard dance by hooking services.exe to use our NtLoadDriver wrapper DLL.

### Building and debugging
You need MSYS2 for building - https://msys2.github.io/

Once you get that, drop into mingw-w64 shell and:

```
MINGW64 ~$ pacman -S mingw-w64-i686-gcc mingw-w64-x86_64-gcc
MINGW64 ~$ git clone https://github.com/katlogic/WindowsD
MINGW64 ~$ cd WindowsD && make
```

To build wind32.exe, just launch the "mingw-w64 win32" shell, and:

```
MINGW32 ~$ cd WindowsD && make clean && make
```

Cross compiling (on linux, or mingw32 from mingw64) is possible, but you'll have to tweak Makefile on your own.

Finally, to get debug version:

```
MINGW64 ~/WindowsD$ make DEBUG=1
```

And you'll see both the userspace exe, dlls and kernel driver tracing heavily into DbgView.
