PREFIX?=/opt/cegcc

CC=$(PREFIX)/bin/arm-mingw32ce-gcc
CXX=$(PREFIX)/bin/arm-mingw32ce-g++
LD=$(PREFIX)/bin/arm-mingw32ce-g++
STRIP=$(PREFIX)/bin/arm-mingw32ce-strip
DLLTOOL=$(PREFIX)/bin/arm-mingw32ce-dlltool
AS=$(PREFIX)/bin/arm-mingw32ce-as
NM=$(PREFIX)/bin/arm-mingw32ce-nm
WINDRES=$(PREFIX)/bin/arm-mingw32ce-windres

OUTPUT=PyAppLauncher.exe

CXXFLAGS= -DEV_PLATFORM_WIN32 -DUNICODE -D_UNICODE -DEV_UNSAFE_SWPRINTF -mwin32 \
-O2 -mcpu=arm926ej-s -D_WIN32_WCE=0x600 -D_LARGEFILE_SOURCE=1 -D_LARGEFILE64_SOURCE=1 \
-D_FILE_OFFSET_BITS=64 -static

.PHONY: all clean format

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT)

format:
	clang-format -i *.c *.h

$(OUTPUT): main.c
	$(CXX) main.c -o $@ $(CXXFLAGS)
	$(STRIP) $@
