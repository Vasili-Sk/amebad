
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
	@$(MAKE) -C xip all
	@$(MAKE) -C sram all
	#$(MAKE) -C rtsp all

#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

	


#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
clean: 
	$(MAKE) -C xip clean
	$(MAKE) -C sram clean
	$(MAKE) -C httpc clean
	$(MAKE) -C httpd clean
	$(MAKE) -C websocket clean
	$(MAKE) -C tftp clean
	$(MAKE) -C rtsp clean
	$(MAKE) -C http2 clean
	$(MAKE) -C eap clean

