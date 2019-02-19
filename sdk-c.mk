NAME := linkkit_sdk_c

$(NAME)_MBINS_TYPE := kernel
$(NAME)_VERSION := 2.3.0
$(NAME)_SUMMARY := IoT Connectivity Devkit Running on Embedded Devices for Alibaba Cloud

$(NAME)_COMPONENTS := middleware/linkkit/hal

GLOBAL_INCLUDES += \
    include/exports \
    include/imports \
    include

#from src/board/config.rhino.make
GLOBAL_CFLAGS  +=

GLOBAL_DEFINES  += BUILD_AOS

GLOBAL_DEFINES   += \
    CONFIG_HTTP_AUTH_TIMEOUT=500 \
    CONFIG_MID_HTTP_TIMEOUT=500 \
    CONFIG_GUIDER_AUTH_TIMEOUT=500 \
    WITH_MQTT_ZIP_TOPIC=1 \
    WITH_MQTT_SUB_SHORTCUT=1 \
    WITH_MQTT_DYN_BUF=1

ROOT_DIR := ../../../
GLOBAL_INCLUDES += $(ROOT_DIR)middleware/linkkit/sdk-c/src/sdk-impl \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/infra/utils/digest \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/infra/utils \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/infra/utils/misc \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/infra/log \
$(ROOT_DIR)middleware/linkkit/sdk-c/include/exports \
$(ROOT_DIR)middleware/linkkit/sdk-c/include/imports \
$(ROOT_DIR)middleware/linkkit/sdk-c/include \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/services/common \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/services/common/os \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/services/common/utility \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/services/awss \
$(ROOT_DIR)middleware/linkkit/sdk-c/src/utils/misc  \

ifeq (y,$(FEATURE_WIFI_PROVISION_ENABLED))
$(NAME)_COMPONENTS += middleware/linkkit/sdk-c/src/services/awss \
    middleware/linkkit/sdk-c/src/services/common
endif

#####################################################################
# Process dependencies of configurations
#
SWITCH_VARS :=  \
    FEATURE_WIFI_PROVISION_ENABLED \
    FEATURE_SUPPORT_ITLS \
    FEATURE_SUPPORT_TLS

SWITCH_VARS += $(shell grep -o 'FEATURE_[_A-Z0-9]*' $(FEATURE_DEFCONFIG_FILES)|cut -d: -f2|uniq)
SWITCH_VARS := $(sort $(SWITCH_VARS))

$(foreach v, \
    $(SWITCH_VARS), \
    $(if $(filter y,$($(v))), \
        $(eval GLOBAL_CFLAGS += -D$(subst FEATURE_,,$(v)))) \
)
