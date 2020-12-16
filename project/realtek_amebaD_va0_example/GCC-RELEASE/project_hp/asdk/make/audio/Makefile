
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
ifeq ($(CONFIG_AUDIO_EN),y)
	$(MAKE) -C ac3 all
	$(MAKE) -C amr	all
	$(MAKE) -C flac all
	$(MAKE) -C haac all
	$(MAKE) -C hmp3 all
	$(MAKE) -C mp3 all
	$(MAKE) -C gsm610 all
	$(MAKE) -C ekho all
	$(MAKE) -C libogg-1.3.3 all
	$(MAKE) -C opus-1.3.1 all
	$(MAKE) -C opusfile-0.11 all
	$(MAKE) -C example_audio_opus_decode all
	$(MAKE) -C libopusenc-0.2.1 all
	$(MAKE) -C example_audio_opus_encode all
endif
#	haac and faac contain same filenames. cannot build at the same time in amebad.
#	$(MAKE) -C g711 all
#	$(MAKE) -C faac all
#	$(MAKE) -C haac all
#	$(MAKE) -C speex all
ifeq ($(CONFIG_BAIDU_DUER),y)
	$(MAKE) -C mp3 all
#	$(MAKE) -C ac3 all
#	$(MAKE) -C haac all
#	$(MAKE) -C hmp3 all
#	$(MAKE) -C m4a_selfparse all
#	$(MAKE) -C m4a all
#	$(MAKE) -C amr	all
endif
#	$(MAKE) -C hls all
#	$(MAKE) -C kws all
#	$(MAKE) -C flac all
	$(MAKE) -C resample all
#*****************************************************************************#
#              GENERATE OBJECT FILE 
#*****************************************************************************#
CORE_TARGETS: $(OBJS)

	


#*****************************************************************************#
#                        RULES TO CLEAN TARGETS                               #
#*****************************************************************************#
clean: 
	$(MAKE) -C mp3 clean
	$(MAKE) -C faac clean
	$(MAKE) -C g711 clean
	$(MAKE) -C haac clean
	$(MAKE) -C speex clean
	$(MAKE) -C amr clean
	$(MAKE) -C ac3 clean
	$(MAKE) -C haac clean
	$(MAKE) -C hmp3 clean
#	$(MAKE) -C m4a_selfparse clean
#	$(MAKE) -C m4a clean
	$(MAKE) -C amr clean
#	$(MAKE) -C hls clean
#	$(MAKE) -C kws clean
	$(MAKE) -C flac clean
	$(MAKE) -C resample clean
	$(MAKE) -C gsm610 clean
	$(MAKE) -C ekho clean
	$(MAKE) -C libogg-1.3.3 clean
	$(MAKE) -C opus-1.3.1 clean
	$(MAKE) -C opusfile-0.11 clean
	$(MAKE) -C example_audio_opus_decode clean
	$(MAKE) -C libopusenc-0.2.1 clean
	$(MAKE) -C example_audio_opus_encode clean
-include $(DEPS)
