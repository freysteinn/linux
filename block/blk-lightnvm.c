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
	int ret;

	if (q->nvm)
		return -EINVAL;

	q->nvm = kmalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!q->nvm)
		return -ENOMEM;

	q->nvm->q = q;

	ret = nvm_init(q, ops);
	if (ret)
		goto err_init;

	return 0;
err_init:
	kfree(q->nvm);
	q->nvm = NULL;
	return ret;
}
EXPORT_SYMBOL(blk_lightnvm_register);

void blk_lightnvm_unregister(struct request_queue *q)
{
	nvm_exit(q);
}
EXPORT_SYMBOL(blk_lightnvm_unregister);

int blk_lightnvm_map(struct nvm_dev *nvm, struct request *rq)
{
	return nvm_map_rq(nvm, rq);
}

int blk_lightnvm_ioctl_kv(struct block_device *bdev,
					unsigned int cmd, char __user *arg)
{
	//return nvm_kv_rq(dev, (void *)arg);
	return 0;
}
