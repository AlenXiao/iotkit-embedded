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

$(call CompLib_Map, FEATURE_COAP_COMM_ENABLED,  src/protocol/coap/cloud)

$(call CompLib_Map, FEATURE_DEVICE_MODEL_ENABLED, \
    src/services/linkkit/ntp \
    src/services/linkkit/dev_reset \
)
$(call CompLib_Map, FEATURE_WIFI_PROVISION_ENABLED, \
    src/protocol/coap/local \
    src/services/awss \
)
$(call CompLib_Map, FEATURE_DEV_BIND_ENABLED, \
    src/protocol/coap/local \
    src/services/dev_bind \
)

# 'Opt1 = y' and 'Opt2 = y' conflicts with each other
#
$(call Conflict_Relation, FEATURE_SUPPORT_TLS, FEATURE_SUPPORT_ITLS)
$(call Conflict_Relation, FEATURE_MAL_ENABLED, FEATURE_MQTT_COMM_ENABLED)

# 'Opt1 = n' and 'Opt2 = n' conflicts with each other
#
$(call Present1_Relation, FEATURE_MQTT_DIRECT, FEATURE_SUPPORT_TLS)


# 'Opt1 = y' requires 'Opt2 = y' as mandantory support
#
$(call Requires_Relation, FEATURE_WIFI_PROVISION_ENABLED, FEATURE_DEV_BIND_ENABLED)

include $(RULE_DIR)/rules.mk
include src/tools/mock_build_options.mk

