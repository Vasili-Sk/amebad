/**
*****************************************************************************************
*     Copyright(c) 2015, Realtek Semiconductor Corporation. All rights reserved.
*****************************************************************************************
  * @file     ais.h
  * @brief    Head file for ali iot service(AIS).
  * @details  Data structs and external functions declaration.
  * @author   bill
  * @date     2018-12-4
  * @version  v1.0
  * *************************************************************************************
  */

/* Define to prevent recursive inclusion */
#ifndef _AIS_H_
#define _AIS_H_

/* Add Includes here */
#include "platform_misc.h"
#include "profile_server.h"
#include "profile_client.h"

BEGIN_DECLS

/** @addtogroup AIS
  * @{
  */

/** @defgroup AIS_Exported_Macros Exported Macros
  * @{
  */

#define AIS_SERVER_TIMEOUT_MSG                          116
#define AIS_SERVER_ADV_PERIOD                           5000

///@cond
/** @brief  Index of each characteristic in service database. */
#define AIS_SERVICE_UUID                                0xFEB3
#define AIS_READ_UUID                                   0xFED4
#define AIS_WRITE_UUID                                  0xFED5
#define AIS_INDICATE_UUID                               0xFED6
#define AIS_WRITE_WO_RESP_UUID                          0xFED7
#define AIS_NOTIFY_UUID                                 0xFED8
///@endcond

/** @} */

/** @defgroup AIS_Exported_Types Exported Types
  * @{
  */

enum
{
    AIS_IMAGE_TYPE_APP,
    AIS_IMAGE_TYPE_PATCH,
    AIS_IMAGE_TYPE_MAX
} _SHORT_ENUM_;
typedef uint8_t ais_image_type_t;

typedef enum
{
    AIS_BT_VER_BLE4_0,
    AIS_BT_VER_BLE4_2,
    AIS_BT_VER_BLE5_0,
    AIS_BT_VER_BLE5_PLUS
} ais_bt_ver_t;

typedef struct
{
    uint8_t bt_ver: 2; /**< @ref ais_bt_ver_t */
    uint8_t ota: 1;
    uint8_t secure: 1;
    uint8_t enc: 1;
    uint8_t adv: 1;
    uint8_t rfu: 2;
} _PACKED_ ais_fmsk_t;

typedef struct
{
    uint8_t vid;
    union
    {
        uint8_t fmsk;
        ais_fmsk_t _fmsk;
    };
    uint32_t pid;
    uint8_t mac[6];
} _PACKED_ ais_adv_data_t;

enum
{
    AIS_DEVICE_REPORT = 0x1,
    AIS_APK_REQ = 0x2,
    AIS_DEVICE_RESP = 0x3,
    AIS_DEVICE_EXCEPTION = 0xf,
    AIS_OTA_GET_VER = 0x20,
    AIS_OTA_REPORT_VER = 0x21,
    AIS_OTA_UPD_REQ = 0x22,
    AIS_OTA_UPD_RESP = 0x23,
    AIS_OTA_FRAME_INFO = 0x24,
    AIS_OTA_FW_INFO_REQ = 0x25,
    AIS_OTA_FW_INFO = 0x26,
    AIS_OTA_FW_DATA = 0x2f,
    AIS_CMD_MAX = 0xff
} _SHORT_ENUM_;
typedef uint8_t ais_cmd_t;

typedef struct
{
    uint8_t msg_id: 4;
    uint8_t enc: 1;
    uint8_t ver: 3;
    ais_cmd_t cmd;
    uint8_t frame_seq: 4;
    uint8_t frame_num: 4;
    uint8_t frame_len;
} _PACKED_ ais_header_t;

typedef struct
{
    ais_image_type_t image_type;
} _PACKED_ ais_ota_get_ver_t;

typedef struct
{
    ais_image_type_t image_type;
    uint32_t ver;
} _PACKED_ ais_ota_report_ver_t;

enum
{
    AIS_OTA_TYPE_FULL,
    AIS_OTA_TYPE_INCREMENT
} _SHORT_ENUM_;
typedef uint8_t ais_ota_type_t;

typedef struct
{
    ais_image_type_t image_type;
    uint32_t ver;
    uint32_t fw_size;
    uint16_t crc16;
    ais_ota_type_t ota_type;
} _PACKED_ ais_ota_upd_req_t;

typedef struct
{
    uint8_t state;
    uint32_t rx_size;
} _PACKED_ ais_ota_upd_resp_t;

typedef struct
{
    uint8_t frame_seq: 4;
    uint8_t frame_num: 4;
    uint32_t rx_size;
} _PACKED_ ais_ota_frame_info_t;

typedef struct
{
    uint8_t state;
} _PACKED_ ais_ota_fw_info_req_t;

typedef struct
{
    uint8_t state;
} _PACKED_ ais_ota_fw_info_t;

typedef struct
{
    uint8_t state;
} _PACKED_ ais_ota_upd_info_t;

typedef struct
{
    ais_header_t header;
    union
    {
        uint8_t payload[1];
        ais_ota_get_ver_t ota_get_ver;
        ais_ota_report_ver_t ota_report_ver;
        ais_ota_upd_req_t ota_upd_req;
        ais_ota_upd_resp_t ota_upd_resp;
        ais_ota_frame_info_t ota_frame_info;
        ais_ota_fw_info_t ota_fw_info;
        ais_ota_upd_info_t ota_upd_info;
        ais_ota_fw_info_req_t ota_fw_info_req;
    };
} _PACKED_ ais_pdu_t;

typedef enum
{
    AIS_CB_READ,
    AIS_CB_WRITE_REQ,
    AIS_CB_OTA,
} ais_cb_type_t;

typedef enum
{
    AIS_OTA_START,
    AIS_OTA_GOING, //!< with
    AIS_OTA_SUCCESS,
    AIS_OTA_FAIL
} ais_ota_state_t;

typedef union
{
    struct
    {
        uint16_t *p_length;
        uint8_t **pp_value;
    } read;
    struct
    {
        ais_pdu_t *pmsg;
        uint16_t msg_len;
    } write_req;
    struct
    {
        ais_ota_state_t state;
        int8_t progress;
    } ota;
} ais_cb_data_t;

/** service data to inform application */
typedef struct
{
    uint8_t conn_id;
    ais_cb_type_t type;
    ais_cb_data_t data;
} ais_cb_msg_t;

extern uint8_t ais_server_id;
/** @} */

/** @defgroup AIS_Exported_Functions Exported Functions
  * @{
  */

/**
  * @brief add service to the stack database.
  * @param[in] pcb: pointer of app callback function called by profile.
  * @return service ID auto generated by profile layer.
  * @retval server_id
  */
uint8_t ais_server_add(void *pcb);

/**
 * @brief send ais advertising
 *
 * @return none
 */
void ais_server_adv(void);

/**
 * @brief stop the ais advertising timer
 *
 * @return none
 */
void ais_server_timer_stop(void);

/** @} */
/** @} */

END_DECLS

#endif  /* _AIS_H_ */
