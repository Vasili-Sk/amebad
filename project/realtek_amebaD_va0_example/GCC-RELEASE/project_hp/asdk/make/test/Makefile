
include $(MAKE_INCLUDE_GEN)


.PHONY: all clean

#*****************************************************************************#
#                               VARIABLES	                              #
#*****************************************************************************#

#*****************************************************************************#
#                               Source FILE LIST                              #
#*****************************************************************************#
OBJS =

#*****************************************************************************#
#                               Include Dependency                            #
#*****************************************************************************#
-include $(OBJS:.o=.d)


#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#
all: 
	$(MAKE) CORE_TARGETS
	$(MAKE) COPY_RAM_OBJS
ifeq ($(CONFIG_PER_TEST),y)
	$(MAKE) -C verification all
endif
ifeq ($(CONFIG_DHRYSTONE_TEST),y)
	$(MAKE) -C coremark all
	$(MAKE) -C dhrystone all
endif
ifeq ($(CONFIG_RTLIB_VERIFY),y)
	$(MAKE) -C std_lib all
	$(MAKE) -C apple all
endif
#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

#*****************************************************************************#
#              CLEAN GENERATED FILES                                          #
#*****************************************************************************#
clean: 
	$(MAKE) -C coremark clean
	$(MAKE) -C dhrystone clean
	$(MAKE) -C std_lib clean
	$(MAKE) -C apple clean
	$(MAKE) -C verification clean

-include $(DEPS)
