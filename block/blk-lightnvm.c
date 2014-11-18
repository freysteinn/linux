/*
 * blk-lightnvm.c - Block layer LightNVM Open-channel SSD integration
 *
 * Copyright (C) 2014 IT University of Copenhagen
 * Written by: Matias Bjorling <mabj@itu.dk>
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

#include <linux/lightnvm.h>
#include <linux/blkdev.h>

int blk_lightnvm_register(struct request_queue *q, struct lightnvm_dev_ops *ops)
{
	struct nvm_dev *nvm;
	int ret;

	if (!ops->identify || !ops->get_features || !ops->set_responsibility)
		return -EINVAL;

	nvm = kmalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!nvm)
		return -ENOMEM;

	nvm->q = q;
	nvm->ops = ops;

	ret = nvm_init(nvm);
	if (ret)
		goto err_init;

	q->nvm = nvm;

	return 0;
err_init:
	kfree(nvm);
	return ret;
}
EXPORT_SYMBOL(blk_lightnvm_register);

void blk_lightnvm_unregister(struct request_queue *q)
{
	if (!q->nvm)
		return;

	nvm_exit(q->nvm);
}
EXPORT_SYMBOL(blk_lightnvm_unregister);

int blk_lightnvm_map(struct nvm_dev *nvm, struct request *rq)
{
	if (rq->cmd_flags & REQ_NVM_MAPPED)
		return -EINVAL;

	return nvm_map_rq(nvm, rq);
}

int blk_lightnvm_init_sysfs(struct device *dev)
{
	return nvm_add_sysfs(dev);
}

void blk_lightnvm_remove_sysfs(struct device *dev)
{
	nvm_remove_sysfs(dev);
}

int blk_lightnvm_ioctl_kv(struct block_device *bdev,
					unsigned int cmd, char __user *arg)
{
	//return nvm_kv_rq(dev, (void *)arg);
	return 0;
}
