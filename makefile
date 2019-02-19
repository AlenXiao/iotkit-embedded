include project.mk
include make.settings
include src/tools/default_settings.mk
include src/tools/parse_make_settings.mk
include $(RULE_DIR)/funcs.mk

# CFLAGS  += -DINSPECT_MQTT_FLOW
# CFLAGS  += -DINSPECT_MQTT_LIST

COMP_LIB            := libiot_sdk.a
COMP_LIB_COMPONENTS := \
    src/infra/utils \
    src/infra/log \

$(call CompLib_Map, FEATURE_WIFI_PROVISION_ENABLED, \
    src/services/awss \
    src/services/common \
)


# 'Opt1 = y' requires 'Opt2 = y' as mandantory support
#
$(call Requires_Relation, FEATURE_WIFI_PROVISION_ENABLED, FEATURE_DEV_BIND_ENABLED)

include $(RULE_DIR)/rules.mk
include src/tools/mock_build_options.mk

