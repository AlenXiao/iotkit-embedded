DEPENDS             := src/ref-impl/hal
DEPENDS             += src/ref-impl/tls

HDR_REFS            += src/infra
HDR_REFS            += src/services

LDFLAGS             := -Bstatic
LDFLAGS             += -liot_sdk

LDFLAGS             += -liot_hal
CFLAGS              := $(filter-out -ansi,$(CFLAGS))
ifneq (,$(filter -D_PLATFORM_IS_LINUX_,$(CFLAGS)))
LDFLAGS             += -lnl
endif
ifneq (,$(filter -D_PLATFORM_IS_WINDOWS_,$(CFLAGS)))
LDFLAGS             += -lws2_32
CFLAGS              := $(filter-out -DCOAP_COMM_ENABLED,$(CFLAGS))
endif
ifneq (,$(filter -DSUPPORT_ITLS,$(CFLAGS)))
LDFLAGS             += -litls
else
LDFLAGS             += -liot_tls
endif

SRCS_awss-example               := app_entry.c

# Syntax of Append_Conditional
# ---
#
# $(call Append_Conditional, TARGET, \  <-- Operated Variable
#   member1 member2 ...            , \  <-- Appended Members
#   switch1 switch2 ...            , \  <-- All These Switches are Defined
#   switch3 switch4 ...)                <-- All These Switches are Not Defined (Optional)


$(call Append_Conditional, LDFLAGS, \
    -litls \
    -lid2client \
    -lkm \
    -lplat_gen \
    -lalicrypto \
    -lmbedcrypto \
, \
SUPPORT_ITLS, \
SUPPORT_TLS)

