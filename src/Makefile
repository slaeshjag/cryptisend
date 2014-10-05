# Project: cryptisend
include $(TOPDIR)/config.mk
include platform.mk

ifeq ($(strip $(OS)), Windows_NT)
	DEPENDS	+=	cryptisend.res
endif

ifeq ($(BUILDFOR), WIN32)
	DEPENDS	+=	cryptisend.res
endif
ifeq ($(BUILDFOR), WIN64)
	DEPENDS	+=	cryptisend.res
endif

# TODO: Replace with fixed list + platform specific files
SRCFILES	=	$(wildcard *.c)
OBJFILES	=	$(SRCFILES:.c=.o)
.PHONY: all clean

all: $(OBJFILES) $(DEPENDS)
	@echo " [ LD ] $(BIN)"
	@$(CC) $(CFLAGS) $(OBJFILES) -o $(BIN) $(LDFLAGS)
	@echo "Done."
	@echo
	
clean:
	@echo
	@echo " [ RM ] $(OBJFILES)"
	@$(RM) $(OBJFILES)
	@$(RM) cryptisend.res
	@echo "Done."
	@echo 

%.o: %.c %.h
	@echo " [ CC ] src/$<"
	@$(CC) $(CFLAGS) -c -o $@ $<
	
darnit.res:
	@windres cryptisend.rc -O coff -o cryptisend.res

