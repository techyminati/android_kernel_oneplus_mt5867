// SPDX-License-Identifier: ISC
/* Copyright (C) 2021 MediaTek Inc.
 *
 */
#include <linux/module.h>
#include <linux/firmware.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "btmtk.h"

#define VERSION "0.1"

/* It is for mt79xx download rom patch*/
#define MTK_FW_ROM_PATCH_HEADER_SIZE	32
#define MTK_FW_ROM_PATCH_GD_SIZE	64
#define MTK_FW_ROM_PATCH_SEC_MAP_SIZE	64
#define MTK_SEC_MAP_COMMON_SIZE	12

struct btmtk_patch_header {
	u8 datetime[16];
	u8 platform[4];
	__le16 hwver;
	__le16 swver;
	__le32 magicnum;
} __packed;

struct btmtk_global_desc {
	__le32 patch_ver;
	__le32 sub_sys;
	__le32 feature_opt;
	__le32 section_num;
} __packed;

int btmtk_setup_firmware_79xx(struct btusb_data *data, u8 *fwbuf,
			      btusb_mtk_wmt_sync_cmd_t wmt_cmd_sync,
			      btusb_mtk_wmt_download_cmd_t wmt_cmd_download)
{
	struct btmtk_global_desc *globaldesc = NULL;
	struct btmtk_section_map *sectionmap;
	u8 *fw_pos;
	int err = -1;
	int i, status;
	u8 retry = 20;
	u32 section_num, dl_size, section_offset;
	u8 event[LD_PATCH_EVT_LEN] = {0x04, 0xE4, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00}; /* event[7] is status*/

	if (!fwbuf) {
		BT_ERR("%s: please assign a rom patch", __func__);
		err = -1;
		goto err_exit;
	}

	globaldesc = (struct btmtk_global_desc *)(fwbuf + MTK_FW_ROM_PATCH_HEADER_SIZE);

	section_num = le32_to_cpu(globaldesc->section_num);

	fw_pos = kmalloc(UPLOAD_PATCH_UNIT, GFP_ATOMIC);
	if (!fw_pos) {
		BT_ERR("%s: alloc memory failed", __func__);
		err = -1;
		goto err_release_fw;
	}

	for (i = 0; i < section_num; i++) {
		sectionmap = (struct btmtk_section_map *)(fwbuf + MTK_FW_ROM_PATCH_HEADER_SIZE +
			      MTK_FW_ROM_PATCH_GD_SIZE + MTK_FW_ROM_PATCH_SEC_MAP_SIZE * i);

		section_offset = le32_to_cpu(sectionmap->secoffset);
		dl_size = le32_to_cpu(sectionmap->bin_info_spec.dlsize);
		BT_INFO("%s: loop_count = %d, section_offset = 0x%08x, download patch_len = 0x%08x\n",
				__func__, i, section_offset, dl_size);

		if (dl_size > 0) {
			retry = 20;
			do {
				status = wmt_cmd_sync(data, fw_pos, 0,
						event, LD_PATCH_EVT_LEN - 1, sectionmap);
				BT_INFO("%s: patch_status %d", __func__, status);

				if (status > PATCH_NEED_DOWNLOAD || status == PATCH_ERR) {
					BT_ERR("%s: patch_status error", __func__);
					err = -1;
					goto err_release_fw;
				} else if (status == PATCH_READY) {
					BT_INFO("%s: no need to load rom patch section%d", __func__, i);
					goto next_section;
				} else if (status == PATCH_IS_DOWNLOAD_BY_OTHER) {
					msleep(100);
					retry--;
				} else if (status == PATCH_NEED_DOWNLOAD) {
					break;  /* Download ROM patch directly */
				}
			} while (retry > 0);

			/* using legacy wmt cmd to download fw patch */
			err = wmt_cmd_download(data, fw_pos, fwbuf, event,
					LD_PATCH_EVT_LEN - 1, dl_size, section_offset);
			if (err < 0) {
				BT_ERR("%s: btmtk_load_fw_patch_using_wmt_cmd failed!", __func__);
				goto err_release_fw;
			}
		}
next_section:
		continue;
	}
	/* Wait a few moments for firmware activation done */
	//usleep_range(100000, 120000);

err_release_fw:
	kfree(fw_pos);
	fw_pos = NULL;
	return err;
err_exit:
	return err;
}
EXPORT_SYMBOL_GPL(btmtk_setup_firmware_79xx);

int btmtk_setup_firmware(struct btusb_data *data, u8 *fwbuf, u32 fwbuf_len,
			 btusb_mtk_wmt_check_dl_patch_t wmt_dl_patch_check,
			 btusb_mtk_wmt_cfg_cmd_t wmt_cfg_cmd,
			 btusb_mtk_wmt_dl_cmd_t wmt_dl_cmd)
{
	char *tmp_str;
	u32 patch_len = 0;
	int patch_status = 0;
	int retry = 20;
	int ret = 0;
	BT_INFO("%s: begin", __func__);

	tmp_str = fwbuf;
	do {
		patch_status = wmt_dl_patch_check(data);
		BT_INFO("%s: patch_status %d!", __func__, patch_status);

		if (patch_status > PATCH_NEED_DOWNLOAD || patch_status == PATCH_ERR) {
			BT_ERR("%s: patch_status error", __func__);
			ret = -1;
			goto exit;
		} else if (patch_status == PATCH_READY) {
			BT_INFO("%s: no need to load rom patch", __func__);
			goto patch_end;
		} else if (patch_status == PATCH_IS_DOWNLOAD_BY_OTHER) {
			msleep(100);
			retry--;
		} else if (patch_status == PATCH_NEED_DOWNLOAD) {
			ret = wmt_cfg_cmd(data);
			if (ret < 0) {
				BT_ERR("%s: send wmt cmd failed(%d)", __func__, ret);
				return ret;
			}
			break;  /* Download ROM patch directly */
		}
	} while(retry > 0);

	tmp_str = fwbuf + 16;
	BT_INFO("%s: platform = %c%c%c%c", __func__, tmp_str[0], tmp_str[1], tmp_str[2], tmp_str[3]);

	tmp_str = fwbuf + 20;
	BT_INFO("%s: HW/SW version = %c%c%c%c", __func__, tmp_str[0], tmp_str[1], tmp_str[2], tmp_str[3]);

	tmp_str = fwbuf + 24;

	BT_INFO("loading rom patch...");

	patch_len = fwbuf_len - PATCH_INFO_SIZE;
	BT_INFO("%s: loading ILM rom patch...patch len %d", __func__, patch_len);
	ret = wmt_dl_cmd(data, fwbuf, patch_len, PATCH_INFO_SIZE);
	if (ret < 0)
		goto patch_end;
	BT_INFO("%s: loading ILM rom patch... Done", __func__);

patch_end:
	BT_INFO("btmtk_setup_firmware end");

exit:
	return ret;
}
EXPORT_SYMBOL_GPL(btmtk_setup_firmware);

int btmtk_set_bdaddr(struct hci_dev *hdev, const bdaddr_t *bdaddr)
{
	struct sk_buff *skb;
	long ret;

	skb = __hci_cmd_sync(hdev, 0xfc1a, 6, bdaddr, HCI_INIT_TIMEOUT);
	if (IS_ERR(skb)) {
		ret = PTR_ERR(skb);
		bt_dev_err(hdev, "changing Mediatek device address failed (%ld)",
			   ret);
		return ret;
	}
	kfree_skb(skb);

	return 0;
}
EXPORT_SYMBOL_GPL(btmtk_set_bdaddr);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_AUTHOR("Mark Chen <mark-yw.chen@mediatek.com>");
MODULE_DESCRIPTION("Bluetooth support for MediaTek devices ver " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
