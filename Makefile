TRIPLET=$(shell gcc -dumpmachine)
ifeq ($(findstring i686,$(TRIPLET)),)
BITS?=64
else
BITS?=32
endif

ifeq ($(BITS),32)
DDK?=/c/msys64/mingw32/i686-w64-mingw32/include/ddk
else
DDK?=/c/msys64/mingw64/x86_64-w64-mingw32/include/ddk
endif

CC=gcc

TGT=wind$(BITS)
all: $(TGT)

CFLAGS=$(OPT) -municode -Wall -Wno-unused-function
LIBS=-lkernel32 -lntdll -lmsvcrt
FFLAGS=-fno-ident -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-exceptions
LDFLAGS=-Wl,--enable-stdcall-fixup -nostartfiles -Wl,-e_win_main -Wl,--exclude-all-symbols
DLDFLAGS=$(LDFLAGS) -shared -Wl,-e_dll_main -nostartfiles -lntdll -nostdlib -lkernel32 -lmsvcrt -Wl,--exclude-all-symbols
SLDFLAGS=$(LDFLAGS) -shared -Wl,-e_driver_entry -Wl,--subsystem=native -nostartfiles -nostdlib -lntoskrnl -Wl,--exclude-all-symbols
VERSTR=v2.2

ifeq ($(DEBUG),)
OPT=-O2 -DNDEBUG
STRIP=objcopy --strip-all
else
STRIP=echo
OPT=-O0 -ggdb
endif


$(TGT): $(TGT).exe

%.o : %.rc
	windres $< $@


$(TGT).exe : wind.c manifest.xml loader$(BITS).o $(TGT)-dll.o $(TGT)-sys.o defs.h wind.h
	echo -e "1 24 manifest.xml" | windres -o manifest.o
	$(CC) -DVERSTR=\"$(VERSTR)\" wind.c manifest.o loader$(BITS).o $(TGT)-dll.o $(TGT)-sys.o -o $@ $(FFLAGS) $(CFLAGS) $(LIBS) $(LDFLAGS)
	$(STRIP) $@
$(TGT)-sys.o: driver.c defs.h wind.h
	$(CC) -I$(DDK) driver.c -o $(TGT).sys $(FFLAGS) $(CFLAGS) $(SLDFLAGS)
	# Win 8/10 kernel can't stand debug symbol tables :(
	cp $(TGT).sys $(TGT)-dbg.sys
	strip $(TGT).sys
	$(STRIP) $(TGT).sys
	echo -e '#include "defs.h"\nSYS_ID RCDATA "$(TGT).sys"' | windres -o $@
$(TGT)-dll.o: service.c defs.h wind.h
	$(CC) service.c -o $(TGT).dll $(FFLAGS) $(CFLAGS) $(DLDFLAGS)
	$(STRIP) $(TGT).dll
	echo -e '#include "defs.h"\nDLL_ID RCDATA "$(TGT).dll"' | windres -o $@

ifneq ($(LOADERS),)
loader32.rc: win7sp1x86/termdd.sys
	echo -e '#include "defs.h"\nLOADER_ID RCDATA "$<"' | windres -o $@
loader64.rc: win7sp1x64/termdd.sys
	echo -e '#include "defs.h"\nLOADER_ID RCDATA "$<"' | windres -o $@
endif

clean:
	rm -f *.exe *.sys *.dll *.o

