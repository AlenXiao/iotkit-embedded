NAME := libiot_cm

$(NAME)_SOURCES := ./iotx_cm.c \
iotx_cm_mqtt.c \
 
$(NAME)_COMPONENTS := middleware/linkkit/sdk-c/src/infra/utils \
middleware/linkkit/sdk-c/src/infra/log \
middleware/linkkit/sdk-c/src/infra/system \
middleware/linkkit/sdk-c/src/sdk-impl \

$(NAME)_INCLUDES := ../../../../src/infra \
../../../../src/infra/log \
../../../../src/infra/utils \
../../../../src/infra/utils/misc \
../../../../src/infra/utils/digest \
../../../../src/infra/system \
../../../../src/protocol/mqtt \
../../../../src/protocol/mqtt/client \
../../../../src/protocol/mqtt/MQTTPacket \
./example \
./include

