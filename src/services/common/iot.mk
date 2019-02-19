LIBA_TARGET     := libiot_bind.a

HDR_REFS        := src/infra
HDR_REFS        += src/services/awss
HDR_REFS        += src/services/common

CFLAGS          += -DAWSS_SUPPORT_DEV_BIND_STATIS
