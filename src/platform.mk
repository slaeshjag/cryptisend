# Project: cryptisend
# Makefile configurations

PLATFORM=POSIX

ifeq ($(strip $(OS)), Windows_NT)
	#Windows specifics
	PLATFORM=	WIN32
else 
ifeq ($(BUILDFOR), WIN32)
	#Windows specifics, for cross compiling to windows
	PLATFORM=	WIN32
else
ifeq ($(BUILDFOR), WIN64)
	#Windows64 specifics, for cross compiling to windows
	PLATFORM=	WIN32
endif
endif
endif


ifeq ($(PLATFORM), POSIX)
	LDFLAGS	+=	-lssl
endif
