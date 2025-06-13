##################### Platform Configure ######################
EXTRA_CFLAGS += -DCONFIG_LITTLE_ENDIAN
ARCH            ?= $(SUBARCH)
SUBARCH := $(shell uname -m | sed -e s/i.86/x86/ \
                                  -e s/x86_64/x86_64/ \
                                  -e s/arm.*/arm/ \
                                  -e s/aarch64.*/arm64/ \
                                  -e s/ppc.*/powerpc/ \
                                  -e s/mips.*/mips/ \
                                  -e s/riscv.*/riscv/)
CROSS_COMPILE ?=
KVER := $(shell uname -r)
KSRC := /lib/modules/$(KVER)/build
MODDESTDIR := /lib/modules/$(KVER)/kernel/drivers/net/wireless/
INSTALL_PREFIX :=

