## WindowsD - Fixing broken windows (DSE and WinTcb protection levels)

WinD is a party "jailberak" so administrators can remove some
mal-features introduced in modern windows versions. Currently, it can disable:

* Driver signing, including WHQL-only locked systems (secureboot tablets).
* Protected processes (used for DRM, "WinTcb").

WinD works similiarly to [other tools](https://github.com/hfiref0x/DSEFix) which disable DSE, but is
designed to be more user friendly and support for more OS/hardware combinations.

It is also designed to be "transparent", that is anything probing for
"integrity" - typically DRM - will still see the system as locked down,
even if drivers and processes are accessible to system administrator.

The idea is more or less 'run once and forget'.

Only accounts with SeLoadDriverPrivilege (admin) can use it.

### Supported windows versions

Windows 7, 8, 8.1 and 10, 32bit and 64bit on Intel CPUs.
You need to use specific WinD32/64 .exe according to bit-ness of your system.

Vista and server editions *may* work, but are untested.

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

### Bugs

The tool depends on many undocumented windows internals, as such, may break
every windows update. Usually, it will simply refuse to load and you'll see
all restrictions in effect again. There is a small chance it will render system
unbootable too, so before installing via `wind /i`, USE the system restore.

If you get a BSOD, open an issue with exact version of windows and build number.

### API

There is header-only C API - `wind.h` Usage goes like:

* `handle = wind_open()` - open the control device, NULL handle on error
* `wind_ioctl(handle,command,buffer,buflen)` - send command(s)
* `wind_close(handle)` - close the control device

`command` can be one of:

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

### Internals

Just like DSEfix and things similiar to it, we simply load a signed driver,
exploit vulnerability in it to gain access to kernel, and override the
policy with whatever we want. There are some differences too:

* Custom signed driver 0day is used.
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
