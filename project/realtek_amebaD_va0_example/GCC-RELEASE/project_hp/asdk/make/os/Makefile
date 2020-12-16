
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
ifeq ($(CONFIG_KERNEL),y)	
	$(MAKE) -C freertos all
	$(MAKE) -C freertos/freertos_v10.2.0 all
endif

#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

	


#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
clean: 
ifeq ($(CONFIG_KERNEL),y)	
	$(MAKE) -C freertos/freertos_v10.2.0 clean
	$(MAKE) -C freertos clean
	$(MAKE) -C os_dep clean
endif
	



