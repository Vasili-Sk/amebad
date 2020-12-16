/* Driver for USB Mass Storage compliant devices
 * Transport Functions Header File
 */

#ifndef _US_TRANSPORT_H_
#define _US_TRANSPORT_H_

#include <platform_opts.h>

#ifdef CONFIG_USBH_MSC

#include "us_usb.h"

/*
 * usb_stor_bulk_transfer_xxx() return codes, in order of severity
 */

#define USB_STOR_XFER_GOOD	0	/* good transfer                 */
#define USB_STOR_XFER_SHORT	1	/* transferred less than expected */
#define USB_STOR_XFER_STALLED	2	/* endpoint stalled              */
#define USB_STOR_XFER_LONG	3	/* device tried to send too much */
#define USB_STOR_XFER_ERROR	4	/* transfer died in the middle   */

/*
 * Transport return codes
 */

#define USB_STOR_TRANSPORT_GOOD	   0   /* Transport good, command good	   */
#define USB_STOR_TRANSPORT_FAILED  1   /* Transport good, command failed   */
#define USB_STOR_TRANSPORT_NO_SENSE 2  /* Command failed, no auto-sense    */
#define USB_STOR_TRANSPORT_ERROR   3   /* Transport bad (i.e. device dead) */

/*
 * We used to have USB_STOR_XFER_ABORTED and USB_STOR_TRANSPORT_ABORTED
 * return codes.  But now the transport and low-level transfer routines
 * treat an abort as just another error (-ENOENT for a cancelled URB).
 * It is up to the invoke_transport() function to test for aborts and
 * distinguish them from genuine communication errors.
 */

/*
 * CBI accept device specific command
 */
#define US_CBI_ADSC		0

//extern int usb_stor_CB_transport(struct scsi_cmnd *, struct us_data*);
//extern int usb_stor_CB_reset(struct us_data*);
//
//extern int usb_stor_Bulk_transport(struct scsi_cmnd *, struct us_data*);
//extern int usb_stor_Bulk_max_lun(struct us_data*);
//extern int usb_stor_Bulk_reset(struct us_data*);
//
//extern void usb_stor_invoke_transport(struct scsi_cmnd *, struct us_data*);
//extern void usb_stor_stop_transport(struct us_data*);

//extern int usb_stor_control_msg(struct us_data *us, unsigned int pipe,
//		u8 request, u8 requesttype, u16 value, u16 index,
//		void *data, u16 size, int timeout);
//extern int usb_stor_clear_halt(struct us_data *us, unsigned int pipe);
//
//extern int usb_stor_ctrl_transfer(struct us_data *us, unsigned int pipe,
//		u8 request, u8 requesttype, u16 value, u16 index,
//		void *data, u16 size);
//extern int usb_stor_bulk_transfer_buf(struct us_data *us, unsigned int pipe,
//		void *buf, unsigned int length, unsigned int *act_len);
//extern int usb_stor_bulk_transfer_sg(struct us_data *us, unsigned int pipe,
//		void *buf, unsigned int length, int use_sg, int *residual);
//extern int usb_stor_bulk_srb(struct us_data* us, unsigned int pipe,
//		struct scsi_cmnd* srb);
//
extern int usb_stor_port_reset(struct us_data *us);

#endif // CONFIG_USBH_MSC

#endif // _US_TRANSPORT_H_

