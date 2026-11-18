KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD V=1 ccflags-y="-I$(CURDIR)/include -Werror=unused-function"

clean:
	if test -d $(KDIR); then \
		$(MAKE) -C $(KDIR) M=$$PWD clean; \
	fi
	rm -f -- .*.cmd .*.d *.a *.mod *.mod.c *.o *.ko modules.order Module.symvers
