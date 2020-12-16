
include $(MAKE_INCLUDE_GEN)

.PHONY: all lib lib_mp clean


#*****************************************************************************#
#                               Object FILE LIST                              #
#*****************************************************************************#
OBJS = 

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#

# Define the Rules to build the core targets
lib: CORE_TARGETS
	$(MAKE) -C sram lib
	$(MAKE) -C xip lib
	
lib_mp: CORE_TARGETS
	$(MAKE) -C sram lib_mp
	$(MAKE) -C xip lib_mp
all:
	$(MAKE) -C option all

#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

	


#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
clean: 
	$(MAKE) -C sram clean
	$(MAKE) -C xip clean
	$(MAKE) -C option clean
	



