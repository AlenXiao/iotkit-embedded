LIBA_TARGET     := libiot_awss.a

HDR_REFS        := src/infra
HDR_REFS        := src/services/common

ifneq (,$(filter -DWIFI_PROVISION_ENABLED,$(CFLAGS)))
    CFLAGS      += -DAWSS_SUPPORT_APLIST
    CFLAGS      += -DAWSS_SUPPORT_STATIS

    ifneq (,$(filter -DAWSS_SUPPORT_SMARTCONFIG,$(CFLAGS)))
        CFLAGS  += -DAWSS_SUPPORT_SMARTCONFIG \
                   -DAWSS_SUPPORT_SMARTCONFIG_WPS
    endif

    ifeq (,$(filter -DAWSS_SUPPORT_ZEROCONFIG,$(CFLAGS)))
        CFLAGS  += -DAWSS_DISABLE_ENROLLEE \
                   -DAWSS_DISABLE_REGISTRAR
    endif
endif
