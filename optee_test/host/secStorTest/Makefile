# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

include ../../scripts/common.mk
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

include $(TA_DEV_KIT_DIR)/host_include/conf.mk

# By default we expect optee_client exported folder to be on a certain relative
# path, but if the client specifies the OPTEE_CLIENT_EXPORT then that path will
# be used instead.
OPTEE_CLIENT_EXPORT ?= ../../../optee_client/out/export

CC		?= $(CROSS_COMPILE)gcc
CPP		?= $(CROSS_COMPILE)cpp
LD		?= $(CROSS_COMPILE)ld
AR		?= $(CROSS_COMPILE)ar
NM		?= $(CROSS_COMPILE)nm
OBJCOPY		?= $(CROSS_COMPILE)objcopy
OBJDUMP		?= $(CROSS_COMPILE)objdump
READELF		?= $(CROSS_COMPILE)readelf

srcs := secStorCaDebug.c
srcs += secStorCaHandle.c
srcs += secStorCaTest.c

objs 	:= $(patsubst %.c,$(out-dir)/secStorTest/%.o, $(srcs))

CFLAGS += -I./include
CFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include
CFLAGS += -I../../ta/secStorTest/include

TA_DIR ?= /lib/optee_armtz
CFLAGS += -DTA_DIR=\"$(TA_DIR)\"

LDFLAGS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec

.PHONY: all
all: secStorTest

secStorTest: $(objs)
	@echo "  LD      $(out-dir)/xtest/$@"
	$(q)@$(CC) -o $(out-dir)/secStorTest/$@ $+ $(LDFLAGS)

$(out-dir)/secStorTest/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(out-dir)/secStorTest/adbg/src
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) -c $< -o $@

RMDIR := rmdir --ignore-fail-on-non-empty
define rm-build-dirs
	$(q)for d in $1; do $(RMDIR) $(out-dir)/secStorTest/$$d 2> /dev/null; true; done
	$(q)$(RMDIR) $(out-dir)/secStorTest 2> /dev/null; true
	$(q)$(RMDIR) $(out-dir) 2> /dev/null; true
endef

.PHONY: clean
clean:
	@echo '  CLEAN $(out-dir)'
	$(q)rm -f $(out-dir)/secStorTest/secStorTest
	$(q)$(foreach obj,$(objs), rm -f $(obj))
	$(call rm-build-dirs,adbg/src adbg)
