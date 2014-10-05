# Project: cryptisend
# Makefile configurations

BIN		=	$(TOPDIR)/bin/cryptisend.elf

DBGFLAGS	=	-O0 -g -D__DEBUG__
VERSION		=	v.0.1alpha
#DBGFLAGS	=	-O3 -g
#Flags specific for tools
LDTOOLS		:=	$(LDFLAGS)
CTOOLS		:=	$(CFLAGS) -Wall -O3
#General flags
CFLAGS		+=	-Wall $(DBGFLAGS)
PREFIX		=	/usr/local

#Extra install targets
INSTARG		=	

#Makefile tools
RM		=	rm -Rf
MKDIR		=	mkdir -p


ifeq ($(strip $(OS)), Windows_NT)
	#Windows specifics
	BIN	=	$(TOPDIR)/bin/cryptisend.exe
	PREFIX	=	/mingw
else 
ifeq ($(BUILDFOR), WIN32)
	#Windows specifics, for cross compiling to windows
	BIN	=	$(TOPDIR)/bin/cryptisend.exe
	CC	=	i586-mingw32msvc-gcc
	STRIP	=	i586-mingw32msvc-strip
	AR	=	i586-mingw32msvc-ar
else
ifeq ($(BUILDFOR), WIN64)
	#Windows64 specifics, for cross compiling to windows
	BIN	=	$(TOPDIR)/bin/cryptisend.exe
	PREFIX	=	/usr/x86_64-w64-mingw32
	CC	=	x86_64-w64-mingw32-gcc
	STRIP	=	x86_64-w64-mingw32-strip
	AR	=	x86_64-w64-mingw32-ar
else
ifeq ($(strip $(SBOX_UNAME_MACHINE)), arm)
	#Maemo specifics
	INSTARG	+=	$(STRIP)
else
ifneq (,$(findstring -DPANDORA, $(CFLAGS)))
	#Pandora specifics
	PREFIX	=	/usr/local/angstrom/arm/arm-angstrom-linux-gnueabi/usr
	INSTARG	+=	$(STRIP)
else
ifeq ($(BUILDFOR), PANDORA)
	#Pandora specifics
	PREFIX	=	/usr/local
	INSTARG	+=	$(STRIP)
else
	#Linux defaults
	STRIP	=	strip
endif
endif
endif
endif
endif
endif
