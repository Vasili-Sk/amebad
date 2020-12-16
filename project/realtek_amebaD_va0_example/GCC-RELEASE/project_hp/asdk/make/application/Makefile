include $(MAKE_INCLUDE_GEN)

.PHONY: all clean

#*****************************************************************************#
#                               VARIABLES	                              #
#*****************************************************************************#

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#
all:
ifeq ($(CONFIG_BAIDU_DUER),y)
	@$(MAKE) -C baidu all
endif
ifeq ($(CONFIG_MQTT_EN),y)
	@$(MAKE) -C mqtt all
endif
ifeq ($(CONFIG_LINKKIT_AWSS),y)
	@$(MAKE) -C linkkit all
endif
	@$(MAKE) -C xmodem all
	#@$(MAKE) -C airkiss all
#*****************************************************************************#
#              CLEAN GENERATED FILES                                          #
#*****************************************************************************#
clean:
	@$(MAKE) -C baidu clean
	@$(MAKE) -C mqtt clean
	@$(MAKE) -C xmodem clean
	#@$(MAKE) -C airkiss clean
	@$(MAKE) -C linkkit clean
-include $(DEPS)
