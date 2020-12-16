 /******************************************************************************
 *
 * Copyright(c) 2007 - 2018 Realtek Corporation. All rights reserved.
 *
 ******************************************************************************/
#include "platform_opts.h"
#include "platform_autoconf.h"

#include "mmf2_link.h"
#include "mmf2_siso.h"
#include "mmf2_miso.h"

#include "module_isp.h"
#include "module_h264.h"
#include "module_rtsp2.h"
#include "module_audio.h"
#include "module_aac.h"
#include "module_mp4.h"

#include "mmf2_video_config.h"
#include "isp_boot.h"

static mm_context_t* isp_v1_ctx				= NULL;
static mm_context_t* h264_v1_ctx			= NULL;
static mm_context_t* audio_ctx				= NULL;
static mm_context_t* aac_ctx				= NULL;
static mm_context_t* mp4_ctx				= NULL;

static mm_siso_t* siso_audio_aac			= NULL;
static mm_siso_t* siso_isp_h264_v1			= NULL;
static mm_miso_t* miso_h264_aac_mp4			= NULL;

static isp_params_t isp_v1_params = {
	.width    = V1_WIDTH, 
	.height   = V1_HEIGHT,
	.fps      = V1_FPS,
	.slot_num = V1_HW_SLOT,
	.buff_num = V1_SW_SLOT,
	.format   = ISP_FORMAT_YUV420_SEMIPLANAR
};

static h264_params_t h264_v1_params = {
	.width          = V1_WIDTH,
	.height         = V1_HEIGHT,
	.bps            = V1_BITRATE,
	.fps            = V1_FPS,
	.gop            = V1_FPS,
	.rc_mode        = V1_H264_RCMODE,
	.mem_total_size = V1_BUFFER_SIZE,
	.mem_block_size = V1_BLOCK_SIZE,
	.mem_frame_size = V1_FRAME_SIZE
};

static audio_params_t audio_params = {
	.sample_rate = ASR_8KHZ,
	.word_length = WL_16BIT,
	.mic_gain    = MIC_40DB,
	.channel     = 1,
	.enable_aec  = 0
};

static aac_params_t aac_params = {
	.sample_rate = 8000,
	.channel = 1,
	.bit_length = FAAC_INPUT_16BIT,
	.mpeg_version = MPEG4,
	.mem_total_size = 10*1024,
	.mem_block_size = 128,
	.mem_frame_size = 1024
};

static mp4_params_t mp4_v1_params = {
	.width          = V1_WIDTH,
	.height         = V1_HEIGHT,
	.fps            = V1_FPS,
	.gop            = V1_FPS,
	
	.sample_rate = 8000,
	.channel = 1,
	
	.record_length = 30, //seconds
	.record_type = STORAGE_ALL,
	.record_file_num = 3,
	.record_file_name = "AmebaPro_recording",
	.fatfs_buf_size = 224*1024, /* 32kb multiple */
};

#if ISP_BOOT_MODE_ENABLE
#define VIDEO_LEN 30
#define AUDIO_LEN 30
extern isp_boot_cfg_t isp_boot_cfg_global;
int mp4_end_cb(void *parm)
{
	printf("Record end\r\n");
}
void mmf2_example_av_mp4_init(void)
{
	isp_v1_ctx = mm_module_open(&isp_module);
        isp_v1_params.boot_mode = ISP_FAST_BOOT;
	if(isp_v1_ctx){
		mm_module_ctrl(isp_v1_ctx, CMD_ISP_SET_PARAMS, (int)&isp_v1_params);
		int i = 0;
		for(i=0;i<isp_boot_cfg_global.isp_config.hw_slot_num;i++)
			mm_module_ctrl(isp_v1_ctx, CMD_ISP_SET_SELF_BUF, isp_boot_cfg_global.isp_buffer[i]);
		mm_module_ctrl(isp_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_SW_SLOT);
		mm_module_ctrl(isp_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(isp_v1_ctx, CMD_ISP_APPLY, 0);	// start channel 0
                isp_v1_params.boot_mode = ISP_NORMAL_BOOT;
	}else{
		rt_printf("ISP open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}

	h264_v1_ctx = mm_module_open(&h264_module);
	if(h264_v1_ctx){
		mm_module_ctrl(h264_v1_ctx, CMD_H264_SET_PARAMS, (int)&h264_v1_params);
		mm_module_ctrl(h264_v1_ctx, MM_CMD_SET_QUEUE_LEN, VIDEO_LEN);
		mm_module_ctrl(h264_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(h264_v1_ctx, CMD_H264_INIT_MEM_POOL, 0);
		mm_module_ctrl(h264_v1_ctx, CMD_H264_APPLY, 0);
	}else{
		rt_printf("H264 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	siso_isp_h264_v1 = siso_create();
	if(siso_isp_h264_v1){
		siso_ctrl(siso_isp_h264_v1, MMIC_CMD_ADD_INPUT, (uint32_t)isp_v1_ctx, 0);
		siso_ctrl(siso_isp_h264_v1, MMIC_CMD_ADD_OUTPUT, (uint32_t)h264_v1_ctx, 0);
		siso_start(siso_isp_h264_v1);
	}else{
	rt_printf("siso_isp_h264_v1 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("siso_isp_h264_v1 started\n\r");
	
	audio_ctx = mm_module_open(&audio_module);
	if(audio_ctx){
		mm_module_ctrl(audio_ctx, CMD_AUDIO_SET_PARAMS, (int)&audio_params);
		mm_module_ctrl(audio_ctx, MM_CMD_SET_QUEUE_LEN, AUDIO_LEN);
		mm_module_ctrl(audio_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(audio_ctx, CMD_AUDIO_APPLY, 0);
	}else{
		rt_printf("AUDIO open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	aac_ctx = mm_module_open(&aac_module);
	if(aac_ctx){
		mm_module_ctrl(aac_ctx, CMD_AAC_SET_PARAMS, (int)&aac_params);
		mm_module_ctrl(aac_ctx, MM_CMD_SET_QUEUE_LEN, AUDIO_LEN);
		mm_module_ctrl(aac_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(aac_ctx, CMD_AAC_INIT_MEM_POOL, 0);
		mm_module_ctrl(aac_ctx, CMD_AAC_APPLY, 0);
	}else{
		rt_printf("AAC open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	mp4_ctx = mm_module_open(&mp4_module);
        mp4_v1_params.record_file_num = 1;
        mp4_v1_params.record_length = 10;
	if(mp4_ctx){
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_PARAMS, (int)&mp4_v1_params);
		mm_module_ctrl(mp4_ctx, CMD_MP4_START, mp4_v1_params.record_file_num);
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_END_CB,(int)mp4_end_cb);
		//mm_module_ctrl(mp4_ctx, MM_CMD_SET_QUEUE_LEN, 3);	
		//mm_module_ctrl(mp4_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
	}else{
		rt_printf("MP4 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("MP4 opened\n\r");
	
	siso_audio_aac = siso_create();
	if(siso_audio_aac){
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_INPUT, (uint32_t)audio_ctx, 0);
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_OUTPUT, (uint32_t)aac_ctx, 0);
		siso_start(siso_audio_aac);
	}else{
		rt_printf("siso1 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("siso1 started\n\r");

	miso_h264_aac_mp4 = miso_create();
	if(miso_h264_aac_mp4){
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_INPUT0, (uint32_t)h264_v1_ctx, 0);
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_INPUT1, (uint32_t)aac_ctx, 0);
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_OUTPUT, (uint32_t)mp4_ctx, 0);
		miso_start(miso_h264_aac_mp4);
	}else{
		rt_printf("miso open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	rt_printf("miso started\n\r");
	
#if 1
	//vTaskDelay(1000);
        pre_example_entry();
#if defined(CONFIG_WIFI_NORMAL) && defined(CONFIG_NETWORK)
	wlan_network();
#endif
#endif
	return;
mmf2_exmaple_av_mp4_fail:
	
	return;
}
#else
int mp4_stop_cb(void *parm)
{
	printf("Record stop\r\n");
}
int mp4_end_cb(void *parm)
{
	printf("Record end\r\n");
}
void mmf2_example_av_mp4_init(void)
{
	isp_v1_ctx = mm_module_open(&isp_module);
	if(isp_v1_ctx){
		mm_module_ctrl(isp_v1_ctx, CMD_ISP_SET_PARAMS, (int)&isp_v1_params);
		mm_module_ctrl(isp_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_SW_SLOT);
		mm_module_ctrl(isp_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(isp_v1_ctx, CMD_ISP_APPLY, 0);	// start channel 0
	}else{
		rt_printf("ISP open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	h264_v1_ctx = mm_module_open(&h264_module);
	if(h264_v1_ctx){
		mm_module_ctrl(h264_v1_ctx, CMD_H264_SET_PARAMS, (int)&h264_v1_params);
		mm_module_ctrl(h264_v1_ctx, MM_CMD_SET_QUEUE_LEN, V1_H264_QUEUE_LEN);
		mm_module_ctrl(h264_v1_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(h264_v1_ctx, CMD_H264_INIT_MEM_POOL, 0);
		mm_module_ctrl(h264_v1_ctx, CMD_H264_APPLY, 0);
	}else{
		rt_printf("H264 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}	
	
	audio_ctx = mm_module_open(&audio_module);
	if(audio_ctx){
		mm_module_ctrl(audio_ctx, CMD_AUDIO_SET_PARAMS, (int)&audio_params);
		mm_module_ctrl(audio_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(audio_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
		mm_module_ctrl(audio_ctx, CMD_AUDIO_APPLY, 0);
	}else{
		rt_printf("AUDIO open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	aac_ctx = mm_module_open(&aac_module);
	if(aac_ctx){
		mm_module_ctrl(aac_ctx, CMD_AAC_SET_PARAMS, (int)&aac_params);
		mm_module_ctrl(aac_ctx, MM_CMD_SET_QUEUE_LEN, 6);
		mm_module_ctrl(aac_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_DYNAMIC);
		mm_module_ctrl(aac_ctx, CMD_AAC_INIT_MEM_POOL, 0);
		mm_module_ctrl(aac_ctx, CMD_AAC_APPLY, 0);
	}else{
		rt_printf("AAC open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	mp4_ctx = mm_module_open(&mp4_module);
	if(mp4_ctx){
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_PARAMS, (int)&mp4_v1_params);
		mm_module_ctrl(mp4_ctx, CMD_MP4_START, mp4_v1_params.record_file_num);
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_STOP_CB,(int)mp4_stop_cb);
		mm_module_ctrl(mp4_ctx, CMD_MP4_SET_END_CB,(int)mp4_end_cb);
		//mm_module_ctrl(mp4_ctx, MM_CMD_SET_QUEUE_LEN, 3);	
		//mm_module_ctrl(mp4_ctx, MM_CMD_INIT_QUEUE_ITEMS, MMQI_FLAG_STATIC);
	}else{
		rt_printf("MP4 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("MP4 opened\n\r");
	
	siso_audio_aac = siso_create();
	if(siso_audio_aac){
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_INPUT, (uint32_t)audio_ctx, 0);
		siso_ctrl(siso_audio_aac, MMIC_CMD_ADD_OUTPUT, (uint32_t)aac_ctx, 0);
		siso_start(siso_audio_aac);
	}else{
		rt_printf("siso1 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("siso1 started\n\r");
	
	siso_isp_h264_v1 = siso_create();
	if(siso_isp_h264_v1){
		siso_ctrl(siso_isp_h264_v1, MMIC_CMD_ADD_INPUT, (uint32_t)isp_v1_ctx, 0);
		siso_ctrl(siso_isp_h264_v1, MMIC_CMD_ADD_OUTPUT, (uint32_t)h264_v1_ctx, 0);
		siso_start(siso_isp_h264_v1);
	}else{
		rt_printf("siso2 open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	
	rt_printf("siso2 started\n\r");
	
	miso_h264_aac_mp4 = miso_create();
	if(miso_h264_aac_mp4){
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_INPUT0, (uint32_t)h264_v1_ctx, 0);
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_INPUT1, (uint32_t)aac_ctx, 0);
		miso_ctrl(miso_h264_aac_mp4, MMIC_CMD_ADD_OUTPUT, (uint32_t)mp4_ctx, 0);
		miso_start(miso_h264_aac_mp4);
	}else{
		rt_printf("miso open fail\n\r");
		goto mmf2_exmaple_av_mp4_fail;
	}
	rt_printf("miso started\n\r");
	
	snapshot_setting(h264_v1_ctx);
	
	return;
mmf2_exmaple_av_mp4_fail:
	
	return;
}
#endif