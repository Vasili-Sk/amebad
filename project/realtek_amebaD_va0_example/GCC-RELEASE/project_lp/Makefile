include ./asdk/config/.config

.PHONY: all clean flash debug setup

#*****************************************************************************#
#                               Object FILE LIST                              #
#*****************************************************************************#
OBJS = 

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#

# Define the Rules to build the core targets
all: CORE_TARGETS
	# $(MAKE) -C asdk flashloader
	$(MAKE) -C asdk bootloader
ifeq ($(CONFIG_USER_CTRL_PS),y)
	$(MAKE) -C asdk ucps_image2
else
	$(MAKE) -C asdk image2
endif
	

setup:
	$(MAKE) -C asdk $(MAKECMDGOALS)

flash:
	$(MAKE) -C asdk gdb

debug:
	$(MAKE) -C asdk debug
	
xip: CORE_TARGETS
	$(MAKE) -C asdk lib_all
	$(MAKE) -C asdk flashloader
	$(MAKE) -C asdk bootloader
ifeq ($(CONFIG_USER_CTRL_PS),y)
	$(MAKE) -C asdk ucps_image2
else
	$(MAKE) -C asdk image2
endif

rom_debug_if_need: CORE_TARGETS
	$(MAKE) -C asdk rom
	$(MAKE) -C asdk copy_rom

imgtool_flashloader:
	$(MAKE) -C asdk imgtool_flashloader

clean: CORE_TARGETS
	$(MAKE) -C asdk clean

clean_all: CORE_TARGETS
	#$(MAKE) -C asdk clean_rom
	$(MAKE) -C asdk clean_all

menuconfig: CORE_TARGETS
	$(MAKE) -C asdk menuconfig

gdb: CORE_TARGETS
	$(MAKE) -C asdk gdb #step2: load flash if need
	#please use tools\AmebaZ\Image Tool!!!!!!!!!!!!!!!!!!
	#user guide: WS_20160928_WLAN5_AmebaZ_Image_Tool_User_Guide_1v0

gdbloadrom: CORE_TARGETS
	$(MAKE) -C asdk gdbloadrom #step1: load rom if need

swdpwd: CORE_TARGETS
	$(MAKE) -C asdk swdpwd

#image2: CORE_TARGETS
#	$(MAKE) -C asdk image2
#
#bootloader: CORE_TARGETS
#	$(MAKE) -C asdk bootloader
#
#flashloader:
#	$(MAKE) -C asdk flashloader
#
#
#gdbboot: CORE_TARGETS
#	$(MAKE) -C asdk gdbboot #boot from RAM
#
#gdbbootxip: CORE_TARGETS
#	$(MAKE) -C asdk gdbbootxip #step3: boot from flash
#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

