static HANDLE ioctl_open()
{
	// Our driver does not install a symlink (so we can survive mountmgr
	// restarts). We have to use NT for access.
	OBJECT_ATTRIBUTES attr = {
		.Length = sizeof(attr),
		.Attributes = OBJ_CASE_INSENSITIVE,
		.ObjectName = &RTL_STRING(L"\\Device\\" IO_DEVNAME),
	};
	IO_STATUS_BLOCK io;
	HANDLE dev;

	NTSTATUS status = NtOpenFile(&dev, FILE_GENERIC_READ, &attr, &io,
		FILE_SHARE_READ,FILE_NON_DIRECTORY_FILE| FILE_SYNCHRONOUS_IO_NONALERT);
	DBG("open=%08x", (unsigned)status);
	if (status == STATUS_NOT_FOUND)
		return NULL;
	if (!NT_SUCCESS(status))
		return NULL;
	return dev;
}

static NTSTATUS ioctl_insmod(HANDLE dev, WCHAR *svc)
{
	DBG("insmod %S",svc);
	IO_STATUS_BLOCK io;
	return NtDeviceIoControlFile(dev, NULL, NULL, NULL, &io, IOCTL_INSMOD,
			svc, wcslen(svc)*2+2, NULL, 0);
}

static NTSTATUS ioctl_setup(HANDLE dev, ULONG_PTR ci, ULONG_PTR orig)
{
	IO_STATUS_BLOCK io;
	UINT_PTR buf[2] = {ci,orig};
	return NtDeviceIoControlFile(dev, NULL, NULL, NULL, &io, IOCTL_SETUP,
			buf, sizeof(buf), NULL, 0);
}


static NTSTATUS ioctl_close(HANDLE dev)
{
	if (dev)
		return NtClose(dev);
	return 0;
}
