/*
 * nvme-lightnvm.c - LightNVM NVMe device
 *
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release:
 *	- Matias Bjorling <mabj@itu.dk>
 *	- Javier González <javier@paletta.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/nvme.h>
#include <linux/bitops.h>
#include <linux/blk-mq.h>
#include <linux/lightnvm.h>

#ifdef CONFIG_NVM

static int nvme_nvm_identify_cmd(struct nvme_dev *dev, u32 chnl_off,
							dma_addr_t dma_addr)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.common.opcode = nvme_nvm_admin_identify;
	c.common.nsid = cpu_to_le32(chnl_off);
	c.common.prp1 = cpu_to_le64(dma_addr);

	return nvme_submit_admin_cmd(dev, &c, NULL);
}

static int nvme_nvm_get_features_cmd(struct nvme_dev *dev, unsigned nsid,
							dma_addr_t dma_addr)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.common.opcode = nvme_nvm_admin_get_features;
	c.common.nsid = cpu_to_le32(nsid);
	c.common.prp1 = cpu_to_le64(dma_addr);

	return nvme_submit_admin_cmd(dev, &c, NULL);
}

static int nvme_nvm_set_resp_cmd(struct nvme_dev *dev, unsigned nsid, u64 resp)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.nvm_resp.opcode = nvme_nvm_admin_set_resp;
	c.nvm_resp.nsid = cpu_to_le32(nsid);
	c.nvm_resp.resp = cpu_to_le64(resp);

	return nvme_submit_admin_cmd(dev, &c, NULL);
}

static int nvme_nvm_get_l2p_tbl_cmd(struct nvme_dev *dev, unsigned nsid,
			u64 slba, u32 nlb, u16 dma_npages, struct nvme_iod *iod)
{
	struct nvme_command c;
	unsigned length;

	length = nvme_setup_prps(dev, iod, iod->length, GFP_KERNEL);
	if ((length >> 12) != dma_npages)
		return -ENOMEM;

	memset(&c, 0, sizeof(c));
	c.nvm_l2p.opcode = nvme_nvm_admin_get_l2p_tbl;
	c.nvm_l2p.nsid = cpu_to_le32(nsid);
	c.nvm_l2p.slba = cpu_to_le64(slba);
	c.nvm_l2p.nlb = cpu_to_le32(nlb);
	c.nvm_l2p.prp1_len = cpu_to_le16(dma_npages);
	c.nvm_l2p.prp1 = cpu_to_le64(sg_dma_address(iod->sg));
	c.nvm_l2p.prp2 = cpu_to_le64(iod->first_dma);

	return nvme_submit_admin_cmd(dev, &c, NULL);
}

static int nvme_nvm_get_bb_tbl_cmd(struct nvme_dev *dev, unsigned nsid, u32 lbb,
					struct nvme_iod *iod)
{
	struct nvme_command c;
	unsigned length;

	memset(&c, 0, sizeof(c));
	c.nvm_get_bb.opcode = nvme_nvm_admin_get_bb_tbl;
	c.nvm_get_bb.nsid = cpu_to_le32(nsid);
	c.nvm_get_bb.lbb = cpu_to_le32(lbb);

	length = nvme_setup_prps(dev, iod, iod->length, GFP_KERNEL);

	c.nvm_get_bb.prp1_len = cpu_to_le32(length);
	c.nvm_get_bb.prp1 = cpu_to_le64(sg_dma_address(iod->sg));
	c.nvm_get_bb.prp2 = cpu_to_le64(iod->first_dma);

	return nvme_submit_admin_cmd(dev, &c, NULL);
}

static int nvme_nvm_erase_blk_cmd(struct nvme_dev *dev, struct nvme_ns *ns,
						sector_t block_id)
{
	struct nvme_command c;
	int nsid = ns->ns_id;

	memset(&c, 0, sizeof(c));
	c.nvm_erase.opcode = nvme_nvm_cmd_erase;
	c.nvm_erase.nsid = cpu_to_le32(nsid);
	c.nvm_erase.blk_addr = cpu_to_le64(block_id);

	return nvme_submit_io_cmd(dev, ns, &c, NULL);
}

static int init_chnls(struct nvme_dev *dev, struct nvm_id *nvm_id,
			struct nvme_nvm_id *dma_buf, dma_addr_t dma_addr)
{
	struct nvme_nvm_id_chnl *src = dma_buf->chnls;
	struct nvm_id_chnl *dst = nvm_id->chnls;
	unsigned int len = nvm_id->nchannels;
	int i, end, off = 0;

	while (len) {
		end = min_t(u32, NVME_NVM_CHNLS_PR_REQ, len);

		for (i = 0; i < end; i++, dst++, src++) {
			dst->laddr_begin = le64_to_cpu(src->laddr_begin);
			dst->laddr_end = le64_to_cpu(src->laddr_end);
			dst->oob_size = le32_to_cpu(src->oob_size);
			dst->queue_size = le32_to_cpu(src->queue_size);
			dst->gran_read = le32_to_cpu(src->gran_read);
			dst->gran_write = le32_to_cpu(src->gran_write);
			dst->gran_erase = le32_to_cpu(src->gran_erase);
			dst->t_r = le32_to_cpu(src->t_r);
			dst->t_sqr = le32_to_cpu(src->t_sqr);
			dst->t_w = le32_to_cpu(src->t_w);
			dst->t_sqw = le32_to_cpu(src->t_sqw);
			dst->t_e = le32_to_cpu(src->t_e);
			dst->io_sched = src->io_sched;
		}

		len -= end;
		if (!len)
			break;

		off += end;

		if (nvme_nvm_identify_cmd(dev, off, dma_addr))
			return -EIO;

		src = dma_buf->chnls;
	}
	return 0;
}

static struct nvme_iod *nvme_get_dma_iod(struct nvme_dev *dev, void *buf,
								unsigned length)
{
	struct scatterlist *sg;
	struct nvme_iod *iod;
	struct device *ddev = &dev->pci_dev->dev;

	if (!length || length > INT_MAX - PAGE_SIZE)
		return ERR_PTR(-EINVAL);

	iod = nvme_alloc_phys_seg_iod(1, length, dev, 0, GFP_KERNEL);
	if (!iod)
		goto err;

	sg = iod->sg;
	sg_init_one(sg, buf, length);
	iod->nents = 1;
	dma_map_sg(ddev, sg, iod->nents, DMA_FROM_DEVICE);

	return iod;
err:
	return ERR_PTR(-ENOMEM);
}

static int nvme_nvm_identify(struct request_queue *q, struct nvm_id *nvm_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct pci_dev *pdev = dev->pci_dev;
	struct nvme_nvm_id *ctrl;
	dma_addr_t dma_addr;
	unsigned int ret;

	ctrl = dma_alloc_coherent(&pdev->dev, 4096, &dma_addr, GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	ret = nvme_nvm_identify_cmd(dev, 0, dma_addr);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	nvm_id->ver_id = ctrl->ver_id;
	nvm_id->nvm_type = ctrl->nvm_type;
	nvm_id->nchannels = le16_to_cpu(ctrl->nchannels);

	if (!nvm_id->chnls)
		nvm_id->chnls = kmalloc(sizeof(struct nvm_id_chnl)
					* nvm_id->nchannels, GFP_KERNEL);

	if (!nvm_id->chnls) {
		ret = -ENOMEM;
		goto out;
	}

	ret = init_chnls(dev, nvm_id, ctrl, dma_addr);
out:
	dma_free_coherent(&pdev->dev, 4096, ctrl, dma_addr);
	return ret;
}

static int nvme_nvm_get_features(struct request_queue *q,
						struct nvm_get_features *gf)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct pci_dev *pdev = dev->pci_dev;
	dma_addr_t dma_addr;
	int ret = 0;
	u64 *mem;

	mem = (u64 *)dma_alloc_coherent(&pdev->dev,
					sizeof(struct nvm_get_features),
							&dma_addr, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	ret = nvme_nvm_get_features_cmd(dev, ns->ns_id, dma_addr);
	if (ret)
		goto finish;

	gf->rsp = le64_to_cpu(mem[0]);
	gf->ext = le64_to_cpu(mem[1]);

finish:
	dma_free_coherent(&pdev->dev, sizeof(struct nvm_get_features), mem,
								dma_addr);
	return ret;
}

static int nvme_nvm_set_resp(struct request_queue *q, u64 resp)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;

	return nvme_nvm_set_resp_cmd(dev, ns->ns_id, resp);
}

static int nvme_nvm_get_l2p_tbl(struct request_queue *q, u64 slba, u64 nlb,
				nvm_l2p_update_fn *update_l2p, void *private)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct pci_dev *pdev = dev->pci_dev;
	static const u16 dma_npages = 256U;
	static const u32 length = dma_npages * PAGE_SIZE;
	u64 nlb_pr_dma = length / sizeof(u64);
	struct nvme_iod *iod;
	u64 cmd_slba = slba;
	dma_addr_t dma_addr;
	void *entries;
	int res = 0;

	entries = dma_alloc_coherent(&pdev->dev, length, &dma_addr, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	iod = nvme_get_dma_iod(dev, entries, length);
	if (!iod) {
		res = -ENOMEM;
		goto out;
	}

	while (nlb) {
		u64 cmd_nlb = min_t(u64, nlb_pr_dma, nlb);

		res = nvme_nvm_get_l2p_tbl_cmd(dev, ns->ns_id, cmd_slba,
						(u32)cmd_nlb, dma_npages, iod);
		if (res) {
			dev_err(&pdev->dev, "L2P table transfer failed (%d)\n",
									res);
			res = -EIO;
			goto free_iod;
		}

		if (update_l2p(cmd_slba, cmd_nlb, entries, private)) {
			res = -EINTR;
			goto free_iod;
		}

		cmd_slba += cmd_nlb;
		nlb -= cmd_nlb;
	}

free_iod:
	dma_unmap_sg(&pdev->dev, iod->sg, 1, DMA_FROM_DEVICE);
	nvme_free_iod(dev, iod);
out:
	dma_free_coherent(&pdev->dev, PAGE_SIZE * dma_npages, entries,
								dma_addr);
	return res;
}

static int nvme_nvm_set_bb_tbl(struct request_queue *q, int lunid,
	unsigned int nr_blocks, nvm_bb_update_fn *update_bbtbl, void *private)
{
	/* TODO: implement logic */
	return 0;
}

static int nvme_nvm_get_bb_tbl(struct request_queue *q, int lunid,
	unsigned int nr_blocks, nvm_bb_update_fn *update_bbtbl, void *private)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;
	struct pci_dev *pdev = dev->pci_dev;
	struct nvme_iod *iod;
	dma_addr_t dma_addr;
	u32 cmd_lbb = (u32)lunid;
	void *bb_bitmap;
	u16 bb_bitmap_size;
	int res = 0;

	bb_bitmap_size = ((nr_blocks >> 15) + 1) * PAGE_SIZE;
	bb_bitmap = dma_alloc_coherent(&pdev->dev, bb_bitmap_size, &dma_addr,
								GFP_KERNEL);
	if (!bb_bitmap)
		return -ENOMEM;

	bitmap_zero(bb_bitmap, nr_blocks);

	iod = nvme_get_dma_iod(dev, bb_bitmap, bb_bitmap_size);
	if (!iod) {
		res = -ENOMEM;
		goto out;
	}

	res = nvme_nvm_get_bb_tbl_cmd(dev, ns->ns_id, cmd_lbb, iod);
	if (res) {
		dev_err(&pdev->dev, "Get Bad Block table failed (%d)\n", res);
		res = -EIO;
		goto free_iod;
	}

	res = update_bbtbl(cmd_lbb, bb_bitmap, nr_blocks, private);
	if (res) {
		res = -EINTR;
		goto free_iod;
	}

free_iod:
	nvme_free_iod(dev, iod);
out:
	dma_free_coherent(&pdev->dev, bb_bitmap_size, bb_bitmap, dma_addr);
	return res;
}

static int nvme_nvm_erase_block(struct request_queue *q, sector_t block_id)
{
	struct nvme_ns *ns = q->queuedata;
	struct nvme_dev *dev = ns->dev;

	return nvme_nvm_erase_blk_cmd(dev, ns, block_id);
}

static struct nvm_dev_ops nvme_nvm_dev_ops = {
	.identify		= nvme_nvm_identify,
	.get_features		= nvme_nvm_get_features,
	.set_responsibility	= nvme_nvm_set_resp,
	.get_l2p_tbl		= nvme_nvm_get_l2p_tbl,
	.set_bb_tbl		= nvme_nvm_set_bb_tbl,
	.get_bb_tbl		= nvme_nvm_get_bb_tbl,
	.erase_block		= nvme_nvm_erase_block,
};

#else
static struct nvm_dev_ops nvme_nvm_dev_ops;
#endif /* CONFIG_NVM */

int nvme_nvm_register(struct gendisk *disk)
{
	return nvm_register(disk, &nvme_nvm_dev_ops);
}

