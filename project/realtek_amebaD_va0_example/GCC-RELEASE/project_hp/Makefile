
.PHONY: all clean flash debug setup mp

#*****************************************************************************#
#                               Object FILE LIST                              #
#*****************************************************************************#
OBJS = 

#*****************************************************************************#
#                        RULES TO GENERATE TARGETS                            #
#*****************************************************************************#

# Define the Rules to build the core targets
all: CORE_TARGETS
	$(MAKE) -C asdk image3_s
	$(MAKE) -C asdk bootloader
	$(MAKE) -C asdk image2_ns
	
mp: CORE_TARGETS
	$(MAKE) -C asdk mp_image3_s
	$(MAKE) -C asdk bootloader
	$(MAKE) -C asdk mp_image2_ns
	
image2: CORE_TARGETS
	$(MAKE) -C asdk image2_ns
	
setup:
	$(MAKE) -C asdk $(MAKECMDGOALS)

flash:
	$(MAKE) -C asdk gdb

debug:
	$(MAKE) -C asdk debug

xip: CORE_TARGETS
	$(MAKE) -C asdk lib_all
	$(MAKE) -C asdk image3_s
	$(MAKE) -C asdk bootloader
	$(MAKE) -C asdk image2_ns

rom_debug_if_need: CORE_TARGETS
	$(MAKE) -C asdk rom_ns
	$(MAKE) -C asdk rom
	$(MAKE) -C asdk copy_rom

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


#not use now
#bootloader: CORE_TARGETS
#	$(MAKE) -C asdk bootloader
#img2: CORE_TARGETS
#	$(MAKE) -C asdk image2_ns
#img3: CORE_TARGETS
#	$(MAKE) -C asdk image3_s
#clean_xip: CORE_TARGETS
#	$(MAKE) -C asdk clean_xip
#
#gdb_all: CORE_TARGETS
#	$(MAKE) -C asdk gdb_all
#gdbboot: CORE_TARGETS
#	$(MAKE) -C asdk gdbboot #boot from RAM
#gdbbootxip: CORE_TARGETS
#	$(MAKE) -C asdk gdbbootxip #step3: boot from flash
#gdbloadromall: CORE_TARGETS
#	$(MAKE) -C asdk gdbloadromall #step1: load rom if need
#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

