## WindowsD - Fixing broken windows (DSE and WinTcb protection levels)

WinD is a 3rd party "jailberak" so administrators can remove some
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
a debugger can be attached, hooks can be injected etc. Re-protection is not
supported from command line at this time, you have to use C API for that.

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

`buf->pid` - set to pid you want to change protection flags for.
`buf->prot` - contents of this struct are copied to process protection flags,
but original protection flags of process will be returned back in the same
buffer - ie contents will be swapped.

You can re-protect a process after you're done with it, simply by calling the
ioctl again with same buffer (it holds the original flags) and the `buf->prot`
will be swapped again.

### Internals

Just like DSEfix and things similiar to it, we simply load a signed driver,
exploit vulnerability in it to gain access to kernel, and override the
policy with whatever we want. There are some differences too:

* Custom signed driver 0day is used.
* 32bit support (Win8+ secureboot).
* It can actually coexist with vbox, does not depend on VT support in CPU
  and it even triggers if the driver is already present as we try to load it
  under different name.
* The vulnerable driver is WHQL signed, so it works even on systems restricted
  to WHQL via secureboot env.
* We automate `reset ci_Options` -> `load unsigned` -> `ci_Options restore`
  PatchGuard dance by hooking services.exe to use our NtLoadDriver wrapper DLL.

