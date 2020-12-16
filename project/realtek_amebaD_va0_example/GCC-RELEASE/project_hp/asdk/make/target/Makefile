
include $(MAKE_INCLUDE_GEN)

.PHONY: all clean


#*****************************************************************************#
#                               Object FILE LIST                              #
#*****************************************************************************#
OBJS = 

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#

# Define the Rules to build the core targets
all: CORE_TARGETS
	$(MAKE) -C crypto all
	$(MAKE) -C fwlib all
	$(MAKE) -C misc all
ifeq ($(CONFIG_USB_OTG_EN),y)
	$(MAKE) -C usb_otg all
endif

#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

	


#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
clean: 
	$(MAKE) -C crypto clean
	$(MAKE) -C fwlib clean
	$(MAKE) -C misc clean
	$(MAKE) -C usb_otg clean
	
