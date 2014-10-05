# Project: cryptisend
include config.mk
MAKEFLAGS	+=	--no-print-directory

TOPDIR		=	$(shell pwd)
export TOPDIR

.PHONY: all install strip clean

all:
	@echo " [INIT] bin/"
	@$(MKDIR) bin/
	@echo " [ CD ] src/"
	+@make -C src/
	
	@echo "Build complete."
	@echo 

clean:
	@echo " [ RM ] bin/"
	+@$(RM) bin/
	@echo " [ CD ] src/"
	+@make -C src/ clean
	@echo
	@echo "Source tree cleaned."
	@echo

windows-release:
	@make -f Makefile.release windows-release

windows64-release:
	@make -f Makefile.release windows64-release

linux64-release:
	@make -f Makefile.release linux64-release

strip:
	@echo " [STRP] bin/"
	@strip $(BIN)
	
install: $(INSTARG)
	@echo " [INST] $(BIN)"
	@install -D -m 0755 $(BIN) $(PREFIX)/bin
	@echo
	@echo "cryptisend installed."
	@echo 
