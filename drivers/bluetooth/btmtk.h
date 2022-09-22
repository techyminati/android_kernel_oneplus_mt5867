/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2021 MediaTek Inc. */

#include <linux/usb.h>
#include <linux/usb/quirks.h>

#ifndef ALIGN_4
#define ALIGN_4(_value)             (((_value) + 3) & ~3u)
#endif /* ALIGN_4 */

#define UPLOAD_PATCH_UNIT	1988
#define UPLOAD_PATCH_UNIT_76XX	2048
#define PATCH_INFO_SIZE		30
#define DELAY_TIMES 20
#define RETRY_TIMES 20
#define PATCH_DOWNLOAD_PHASE1_2_DELAY_TIME 1
#define PATCH_DOWNLOAD_PHASE1_2_RETRY 5
#define PATCH_DOWNLOAD_PHASE3_DELAY_TIME 20
#define PATCH_DOWNLOAD_PHASE3_RETRY 20
#define TIME_MULTIPL 1000
#define TIME_US_OFFSET_RANGE 2000
#define PATCH_PHASE1		1
#define PATCH_PHASE2		2
#define PATCH_PHASE3		3
#define HCI_MAX_COMMAND_SIZE 255
#define ERRNUM 0xFF
#define USB_CTRL_IO_TIMO	100
#define MTK_SEC_MAP_NEED_SEND_SIZE	52
#define PATCH_HCI_HEADER_SIZE	4
#define PATCH_WMT_HEADER_SIZE	5
#define PATCH_HEADER_SIZE	(PATCH_HCI_HEADER_SIZE + PATCH_WMT_HEADER_SIZE + 1)
#define PATCH_HEADER_SIZE_76XX	(PATCH_HCI_HEADER_SIZE + PATCH_WMT_HEADER_SIZE)
#define LD_PATCH_EVT_LEN 8
#define PATCH_READY 1
#define PATCH_ERR -1
#define PATCH_IS_DOWNLOAD_BY_OTHER 0
#define PATCH_NEED_DOWNLOAD 2
#define WMT_POWER_ON_CMD_LEN 10
#define WMT_POWER_ON_EVT_HDR_LEN 7
#define BT0_MCU_INTERFACE_NUM 0
#define BT1_MCU_INTERFACE_NUM 3

#define BTMTK_IS_BT_0_INTF(ifnum_base) \
	(ifnum_base == BT0_MCU_INTERFACE_NUM)

#define BTMTK_IS_BT_1_INTF(ifnum_base) \
	(ifnum_base == BT1_MCU_INTERFACE_NUM)

struct btmtk_tci_sleep {
	u8 mode;
	__le16 duration;
	__le16 host_duration;
	u8 host_wakeup_pin;
	u8 time_compensation;
} __packed;

struct reg_read_cmd {
	u8 type;
	u8 rsv;
	u8 num;
	__le32 addr;
} __packed;

struct reg_write_cmd {
	u8 type;
	u8 rsv;
	u8 num;
	__le32 addr;
	__le32 data;
	__le32 mask;
} __packed;

struct btmtk_hci_wmt_params {
	u8 op;
	u8 flag;
	u16 dlen;
	const void *data;
	u32 *status;
};

struct btmtk_section_map {
	__le32 sectype;
	__le32 secoffset;
	__le32 secsize;
	union {
		__le32 u4SecSpec[13];
		struct {
			__le32 dlAddr;
			__le32 dlsize;
			__le32 seckeyidx;
			__le32 alignlen;
			__le32 sectype;
			__le32 dlmodecrctype;
			__le32 crc;
			__le32 reserved[6];
		} bin_info_spec;
	};
} __packed;

struct btusb_data {
	struct hci_dev       *hdev;
	struct usb_device    *udev;
	struct usb_interface *intf;
	struct usb_interface *isoc;
	struct usb_interface *diag;
	unsigned isoc_ifnum;

	unsigned long flags;

	bool poll_sync;
	int intr_interval;
	struct work_struct  work;
	struct work_struct  waker;
	struct delayed_work rx_work;

	struct sk_buff_head acl_q;

	struct usb_anchor deferred;
	struct usb_anchor tx_anchor;
	int tx_in_flight;
	spinlock_t txlock;

	struct usb_anchor intr_anchor;
	struct usb_anchor bulk_anchor;
	struct usb_anchor isoc_anchor;
	struct usb_anchor diag_anchor;
	struct usb_anchor ctrl_anchor;
	spinlock_t rxlock;

	struct sk_buff *evt_skb;
	struct sk_buff *acl_skb;
	struct sk_buff *sco_skb;

	struct usb_endpoint_descriptor *intr_ep;
	struct usb_endpoint_descriptor *bulk_cmd_tx_ep;
	struct usb_endpoint_descriptor *bulk_tx_ep;
	struct usb_endpoint_descriptor *bulk_rx_ep;
	struct usb_endpoint_descriptor *isoc_tx_ep;
	struct usb_endpoint_descriptor *isoc_rx_ep;
	struct usb_endpoint_descriptor *diag_tx_ep;
	struct usb_endpoint_descriptor *diag_rx_ep;

	__u8 cmdreq_type;
	__u8 cmdreq;

	unsigned int sco_num;
	unsigned int air_mode;
	bool usb_alt6_packet_flow;
	int isoc_altsetting;
	int suspend_count;

	int (*recv_event)(struct hci_dev *hdev, struct sk_buff *skb);
	int (*recv_acl)(struct hci_dev *hdev, struct sk_buff *skb);
	int (*recv_bulk)(struct btusb_data *data, void *buffer, int count);

	int (*setup_on_usb)(struct hci_dev *hdev);

	int oob_wake_irq;   /* irq for out-of-band wake-on-bt */
	unsigned cmd_timeout_cnt;
};

typedef int (*wmt_cmd_sync_func_t)(struct hci_dev *,
				   struct btmtk_hci_wmt_params *);

typedef int (*btusb_mtk_wmt_sync_cmd_t)(struct btusb_data *, u8 *,
		int, u8 *, int, struct btmtk_section_map *);

typedef int (*btusb_mtk_wmt_download_cmd_t)(struct btusb_data *,
		u8 *, u8 *, u8 *, int, u32, int);

typedef int (*btusb_mtk_wmt_check_dl_patch_t)(struct btusb_data *);

typedef int (*btusb_mtk_wmt_cfg_cmd_t)(struct btusb_data *);

typedef int (*btusb_mtk_wmt_dl_cmd_t)(struct btusb_data *, u8 *, u32, int);

int btmtk_set_bdaddr(struct hci_dev *hdev, const bdaddr_t *bdaddr);

int btmtk_setup_firmware_79xx(struct btusb_data *data, u8 *fwbuf,
			      btusb_mtk_wmt_sync_cmd_t wmt_cmd_sync,
			      btusb_mtk_wmt_download_cmd_t wmt_cmd_download);

int btmtk_setup_firmware(struct btusb_data *data, u8 *fwbuf, u32 fwbuf_len,
			 btusb_mtk_wmt_check_dl_patch_t wmt_dl_patch_check,
			 btusb_mtk_wmt_cfg_cmd_t wmt_cfg_cmd,
			 btusb_mtk_wmt_dl_cmd_t wmt_dl_cmd);

