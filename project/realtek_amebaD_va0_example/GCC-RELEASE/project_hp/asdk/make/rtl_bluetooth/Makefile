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
all: CORE_TARGETS
ifeq ($(CONFIG_BT_EN),y)
ifeq ($(CONFIG_BT_MESH_PROVISIONER),y)
	$(MAKE) -C mesh_provisioner all
ifeq ($(CONFIG_BT_MESH_PROVISIONER_RTK_DEMO),y)
	$(MAKE) -C bt_mesh_provisioner_rtk_demo all
endif
else ifeq ($(CONFIG_BT_MESH_DEVICE),y)
	$(MAKE) -C mesh_device all
ifeq ($(CONFIG_BT_MESH_DEVICE_RTK_DEMO),y)
	$(MAKE) -C bt_mesh_device_rtk_demo all
endif
else ifeq ($(CONFIG_BT_MESH_PROVISIONER_MULTIPLE_PROFILE),y)
	$(MAKE) -C mesh_provisioner_multiple_profile all
ifeq ($(CONFIG_BT_MESH_PROVISIONER_RTK_DEMO),y)
	$(MAKE) -C bt_mesh_provisioner_rtk_demo all
endif
else ifeq ($(CONFIG_BT_MESH_DEVICE_MULTIPLE_PROFILE),y)	
	$(MAKE) -C mesh_device_multiple_profile all
ifeq ($(CONFIG_BT_MESH_DEVICE_RTK_DEMO),y)
	$(MAKE) -C bt_mesh_device_rtk_demo all
endif
endif
	$(MAKE) -C bt_beacon all
	$(MAKE) -C bt_config all
	$(MAKE) -C bt_airsync_config all
	$(MAKE) -C ble_peripheral all
	$(MAKE) -C ble_central all
	$(MAKE) -C ble_scatternet all
endif

#*****************************************************************************#
#              GENERATE OBJECT FILE
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

#*****************************************************************************#
#              CLEAN GENERATED FILES                                          #
#*****************************************************************************#
clean:
	$(MAKE) -C mesh_provisioner clean
	$(MAKE) -C mesh_device clean
	$(MAKE) -C bt_mesh_provisioner_rtk_demo clean
	$(MAKE) -C bt_mesh_device_rtk_demo clean
	$(MAKE) -C mesh_provisioner_multiple_profile clean
	$(MAKE) -C mesh_device_multiple_profile clean
	$(MAKE) -C bt_beacon clean
	$(MAKE) -C bt_config clean
	$(MAKE) -C bt_airsync_config clean
	$(MAKE) -C ble_peripheral clean
	$(MAKE) -C ble_central clean
	$(MAKE) -C ble_scatternet clean

-include $(DEPS)
