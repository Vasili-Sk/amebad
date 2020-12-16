include $(MAKE_INCLUDE_GEN)

ifeq ($(CONFIG_BT_EN),y)
SUBDIRS += rtl_bluetooth
endif
ifeq ($(CONFIG_WIFI_EN),y)
SUBDIRS += network
SUBDIRS += api
SUBDIRS += wlan
endif
SUBDIRS += utilities
SUBDIRS += test
SUBDIRS += os
ifeq ($(CONFIG_MBED_TLS_ENABLED),y)
SUBDIRS += mbedtls
endif
ifeq ($(CONFIG_GUI_EN),y)
SUBDIRS += ui
endif
#SUBDIRS +=bootloader
SUBDIRS += app
SUBDIRS += target
SUBDIRS += drivers
SUBDIRS += cmsis
SUBDIRS += mbed
SUBDIRS += audio
SUBDIRS += graphic
#SUBDIRS += media
SUBDIRS += utilities_example
SUBDIRS += file_system
SUBDIRS += project
SUBDIRS += application
#SUBDIRS += cmsis-dsp

.PHONY: all clean $(SUBDIRS)
#*****************************************************************************#
#                               VARIABLES	                              #
#*****************************************************************************#

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#
all: $(SUBDIRS)

$(SUBDIRS): 
	$(MAKE) -C $@ all
#all:
#	@$(MAKE) -C  all

#*****************************************************************************#
#              CLEAN GENERATED FILES                                          #
#*****************************************************************************#
clean:
	@$(MAKE) -C application clean
	@$(MAKE) -C wlan clean
	@$(MAKE) -C wps clean
	@$(MAKE) -C network clean
	@$(MAKE) -C api clean
	@$(MAKE) -C utilities clean
	@$(MAKE) -C test clean
	@$(MAKE) -C os clean
	@$(MAKE) -C ssl clean
	@$(MAKE) -C mbedtls clean
	@$(MAKE) -C mbed clean
	@$(MAKE) -C app clean
	@$(MAKE) -C bootloader clean
	@$(MAKE) -C drivers clean
	@$(MAKE) -C target clean
	@$(MAKE) -C rtl_bluetooth clean
	@$(MAKE) -C cmsis clean
	@$(MAKE) -C cmsis-dsp clean
	@$(MAKE) -C mbed clean
	@$(MAKE) -C audio clean
	@$(MAKE) -C graphic clean
	@$(MAKE) -C utilities_example clean
	@$(MAKE) -C file_system clean	
	@$(MAKE) -C project clean
	@$(MAKE) -C ui clean
	@$(MAKE) -C media clean
	@$(MAKE) -C linkkit clean
-include $(DEPS)
