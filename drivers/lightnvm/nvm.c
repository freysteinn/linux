/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * Todo
 *
 * - Implement fetching of bad pages from flash
 * - configurable sector size
 * - handle case of in-page bv_offset (currently hidden assumption of offset=0,
 *   and bv_len spans entire page)
 *
 * Optimization possibilities
 * - Implement per-cpu nvm_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   nvm_block lists.
 */

#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/sem.h>
#include <linux/types.h>
#include <linux/lightnvm.h>

#include <linux/ktime.h>
#include <trace/events/block.h>

#include "nvm.h"

/* Defaults
 * Number of append points per pool. We assume that accesses within a pool is
 * serial (NAND flash/PCM/etc.)
 */
#define APS_PER_POOL 1

/* Run GC every X seconds */
#define GC_TIME 10

/* Minimum pages needed within a pool */
#define MIN_POOL_PAGES 16

extern struct nvm_target_type nvm_target_rrpc;
extern struct nvm_gc_type nvm_gc_greedy;

static struct kmem_cache *_addr_cache;

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

struct nvm_target_type *find_nvm_target_type(const char *name)
{
	struct nvm_target_type *tt;

	list_for_each_entry(tt, &_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *tt)
{
	int ret = 0;

	down_write(&_lock);
	if (find_nvm_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &_targets);
	up_write(&_lock);
	return ret;
}

void nvm_unregister_target(struct nvm_target_type *tt)
{
	if (!tt)
		return;

	down_write(&_lock);
	list_del(&tt->list);
	up_write(&_lock);
}

int nvm_queue_rq(struct nvm_dev *dev, struct request *rq)
{
	struct nvm_stor *s = dev->stor;
	int ret;

	if (rq->cmd_flags & REQ_NVM_MAPPED)
		return BLK_MQ_RQ_QUEUE_OK;

	if (blk_rq_pos(rq) / NR_PHY_IN_LOG > s->nr_pages) {
		pr_err("lightnvm: out-of-bound address: %llu",
					(unsigned long long) blk_rq_pos(rq));
		return BLK_MQ_RQ_QUEUE_ERROR;
	}

	if (rq_data_dir(rq) == WRITE)
		ret = s->type->write_rq(s, rq);
	else
		ret = s->type->read_rq(s, rq);

	if (ret == BLK_MQ_RQ_QUEUE_OK)
		rq->cmd_flags |= (REQ_NVM|REQ_NVM_MAPPED);

	return ret;
}
EXPORT_SYMBOL_GPL(nvm_queue_rq);

void nvm_complete_request(struct nvm_dev *nvm_dev, struct request *rq, int error)
{
	if (rq->cmd_flags & (REQ_NVM|REQ_NVM_MAPPED))
		nvm_endio(nvm_dev, rq, error);

	if (!(rq->cmd_flags & REQ_NVM))
		pr_info("lightnvm: request outside lightnvm detected.\n");
}
EXPORT_SYMBOL_GPL(nvm_complete_request);

unsigned int nvm_cmd_size(void)
{
	return sizeof(struct per_rq_data);
}
EXPORT_SYMBOL_GPL(nvm_cmd_size);

static void nvm_pools_free(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	int i;

	if (s->krqd_wq)
		destroy_workqueue(s->krqd_wq);

	if (s->kgc_wq)
		destroy_workqueue(s->kgc_wq);

	nvm_for_each_pool(s, pool, i) {
		if (!pool->blocks)
			break;
		vfree(pool->blocks);
	}
	kfree(s->pools);
	kfree(s->aps);
}

static int nvm_pools_init(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	struct nvm_block *block;
	struct nvm_ap *ap;
	int i, j;

	spin_lock_init(&s->rev_lock);

	s->pools = kcalloc(s->nr_pools, sizeof(struct nvm_pool), GFP_KERNEL);
	if (!s->pools)
		goto err_pool;

	nvm_for_each_pool(s, pool, i) {
		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);

		pool->id = i;
		pool->s = s;
		pool->phy_addr_start = i * s->nr_blks_per_pool;
		pool->phy_addr_end = (i + 1) * s->nr_blks_per_pool - 1;
		pool->nr_free_blocks = pool->nr_blocks =
				pool->phy_addr_end - pool->phy_addr_start + 1;

		pool->blocks = vzalloc(sizeof(struct nvm_block) *
							pool->nr_blocks);
		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			atomic_set(&block->gc_running, 0);
			INIT_LIST_HEAD(&block->list);


			block->pool = pool;
			block->id = (i * s->nr_blks_per_pool) + j;

			list_add_tail(&block->list, &pool->free_list);
		}
	}

	s->nr_aps = s->nr_aps_per_pool * s->nr_pools;
	s->aps = kcalloc(s->nr_aps, sizeof(struct nvm_ap), GFP_KERNEL);
	if (!s->aps)
		goto err_blocks;

	nvm_for_each_ap(s, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = s;
		ap->pool = &s->pools[i / s->nr_aps_per_pool];

		block = s->type->pool_get_blk(ap->pool, 0);
		nvm_set_ap_cur(ap, block);

		/* Emergency gc block */
		block = s->type->pool_get_blk(ap->pool, 1);
		ap->gc_cur = block;

		ap->t_read = s->config.t_read;
		ap->t_write = s->config.t_write;
		ap->t_erase = s->config.t_erase;
	}

	/* we make room for each pool context. */
	s->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						s->nr_pools);
	if (!s->krqd_wq) {
		pr_err("Couldn't alloc knvm-work");
		goto err_blocks;
	}

	s->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!s->kgc_wq) {
		pr_err("Couldn't alloc knvm-gc");
		goto err_blocks;
	}

	return 0;
err_blocks:
	nvm_pools_free(s);
err_pool:
	pr_err("lightnvm: cannot allocate lightnvm data structures");
	return -ENOMEM;
}

static int nvm_stor_init(struct nvm_dev *dev, struct nvm_stor *s)
{
	int i;

	s->trans_map = vzalloc(sizeof(struct nvm_addr) * s->nr_pages);
	if (!s->trans_map)
		return -ENOMEM;

	s->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* s->nr_pages);
	if (!s->rev_trans_map)
		goto err_rev_trans_map;

	for (i = 0; i < s->nr_pages; i++) {
		struct nvm_addr *p = &s->trans_map[i];
		struct nvm_rev_addr *r = &s->rev_trans_map[i];

		p->addr = LTOP_EMPTY;
		r->addr = 0xDEADBEEF;
	}

	s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
	if (!s->page_pool)
		goto err_dev_lookup;

	s->addr_pool = mempool_create_slab_pool(64, _addr_cache);
	if (!s->addr_pool)
		goto err_page_pool;

	s->sector_size = EXPOSED_PAGE_SIZE;

	/* inflight maintenance */
	percpu_ida_init(&s->free_inflight, NVM_INFLIGHT_TAGS);

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&s->inflight_map[i].lock);
		INIT_LIST_HEAD(&s->inflight_map[i].reqs);
	}

	/* simple round-robin strategy */
	atomic_set(&s->next_write_ap, -1);

	s->dev = (void *)dev;
	dev->stor = s;

	/* Initialize pools. */
	nvm_pools_init(s);

	if (s->type->init && s->type->init(s))
		goto err_addr_pool_tgt;

	if (s->gc_ops->init && s->gc_ops->init(s))
		goto err_addr_pool_gc;

	/* FIXME: Clean up pool init on failure. */
	setup_timer(&s->gc_timer, s->gc_ops->gc_timer, (unsigned long)s);
	mod_timer(&s->gc_timer, jiffies + msecs_to_jiffies(1000));

	return 0;
err_addr_pool_gc:
	s->type->exit(s);
err_addr_pool_tgt:
	nvm_pools_free(s);
	mempool_destroy(s->addr_pool);
err_page_pool:
	mempool_destroy(s->page_pool);
err_dev_lookup:
	vfree(s->rev_trans_map);
err_rev_trans_map:
	vfree(s->trans_map);
	return -ENOMEM;
}

#define NVM_TARGET_TYPE "rrpc"
#define NVM_GC_TYPE "greedy"
#define NVM_NUM_POOLS 8
#define NVM_NUM_BLOCKS 256
#define NVM_NUM_PAGES 256

int nvm_queue_init(struct request_queue *q)
{
	int nr_sectors_per_page = 8; /* 512 bytes */

	if (queue_logical_block_size(q) > (nr_sectors_per_page << 9)) {
		pr_err("nvm: logical page size not supported by hardware");
		return false;
	}

	return true;
}

int nvm_init(struct request_queue *q, struct lightnvm_dev_ops *ops)
{
	struct nvm_dev *nvm = q->nvm;
	struct nvm_stor *s;
	struct nvm_id nvm_id;
	struct nvm_id_chnl *nvm_id_chnl;
	int ret = 0;

	unsigned long size;

	if (!ops->identify || !ops->identify_channel || !ops->get_features ||
						!ops->set_responsibility)
		return -EINVAL;

	nvm->ops = ops;

	if (!nvm_queue_init(q))
		return -EINVAL;

	nvm_id_chnl = kmalloc(sizeof(struct nvm_id_chnl), GFP_KERNEL);
	if (!nvm_id_chnl) {
		ret = -ENOMEM;
		goto err;
	}

	_addr_cache = kmem_cache_create("nvm_addr_cache",
				sizeof(struct nvm_addr), 0, 0, NULL);
	if (!_addr_cache) {
		ret = -ENOMEM;
		goto err_memcache;
	}

	nvm_register_target(&nvm_target_rrpc);

	s = kzalloc(sizeof(struct nvm_stor), GFP_KERNEL);
	if (!s) {
		ret = -ENOMEM;
		goto err_stor;
	}

	/* hardcode initialization values until user-space util is avail. */
	s->type = &nvm_target_rrpc;
	if (!s->type) {
		pr_err("nvm: %s doesn't exist.", NVM_TARGET_TYPE);
		ret = -EINVAL;
		goto err_cfg;
	}

	s->gc_ops = &nvm_gc_greedy;
	if (!s->gc_ops) {
		pr_err("nvm: %s doesn't exist.", NVM_GC_TYPE);
		ret = -EINVAL;
		goto err_cfg;
	}

	if (nvm->ops->identify(q, &nvm_id)) {
		ret = -EINVAL;
		goto err_cfg;
	}

	pr_debug("lightnvm dev: ver %u type %u chnls %u\n",
			nvm_id.ver_id, nvm_id.nvm_type, nvm_id.nchannels);

	s->nr_pools = nvm_id.nchannels;

	/* TODO: We're limited to the same setup for each channel */
	if (nvm->ops->identify_channel(q, 0, nvm_id_chnl)) {
		ret = -EINVAL;
		goto err_cfg;
	}

	pr_debug("lightnvm dev: qsize %llu gr %llu ge %llu begin %llu end %llu\n",
			nvm_id_chnl->queue_size,
			nvm_id_chnl->gran_read, nvm_id_chnl->gran_erase,
			nvm_id_chnl->laddr_begin, nvm_id_chnl->laddr_end);

	s->gran_blk = nvm_id_chnl->gran_erase;
	s->gran_read = nvm_id_chnl->gran_read;
	s->gran_write = nvm_id_chnl->gran_write;

	size = (nvm_id_chnl->laddr_end - nvm_id_chnl->laddr_begin)
					* min(s->gran_read, s->gran_write);

	s->total_blocks = size / s->gran_blk;
	s->nr_blks_per_pool = s->total_blocks / nvm_id.nchannels;
	/* TODO: gran_{read,write} may differ */
	s->nr_pages_per_blk = s->gran_blk / s->gran_read *
					(s->gran_read / EXPOSED_PAGE_SIZE);

	s->nr_aps_per_pool = APS_PER_POOL;
	/* s->config.flags = NVM_OPT_* */
	s->config.gc_time = GC_TIME;
	s->config.t_read = nvm_id_chnl->t_r / 1000;
	s->config.t_write = nvm_id_chnl->t_w / 1000;
	s->config.t_erase = nvm_id_chnl->t_e / 1000;

	/* Constants */
	s->nr_pages = s->nr_pools * s->nr_blks_per_pool * s->nr_pages_per_blk;

	if (s->nr_pages_per_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Num. pages per block too high. Increase MAX_INVALID_PAGES_STORAGE.");
		ret = -EINVAL;
		goto err_cfg;
	}

	ret = nvm_stor_init(nvm, s);
	if (ret < 0) {
		pr_err("lightnvm: cannot initialize nvm structure.");
		goto err_cfg;
	}

	pr_info("lightnvm: pools: %u\n", s->nr_pools);
	pr_info("lightnvm: blocks: %u\n", s->nr_blks_per_pool);
	pr_info("lightnvm: pages per block: %u\n", s->nr_pages_per_blk);
	pr_info("lightnvm: append points: %u\n", s->nr_aps);
	pr_info("lightnvm: append points per pool: %u\n", s->nr_aps_per_pool);
	pr_info("lightnvm: timings: %u/%u/%u\n",
			s->config.t_read,
			s->config.t_write,
			s->config.t_erase);
	pr_info("lightnvm: target sector size=%d\n", s->sector_size);
	pr_info("lightnvm: disk flash size=%d map size=%d\n",
			s->gran_read, EXPOSED_PAGE_SIZE);
	pr_info("lightnvm: allocated %lu physical pages (%lu KB)\n",
			s->nr_pages, s->nr_pages * s->sector_size / 1024);

	nvm->stor = s;
	kfree(nvm_id_chnl);
	return 0;

err_cfg:
	kfree(s);
err_stor:
	kmem_cache_destroy(_addr_cache);
err_memcache:
	kfree(nvm_id_chnl);
err:
	pr_err("lightnvm: failed to initialize nvm\n");
	return ret;
}
EXPORT_SYMBOL_GPL(nvm_init);

void nvm_exit(struct request_queue *q)
{
	struct nvm_dev *nvm = q->nvm;
	struct nvm_stor *s;

	if (!nvm)
		return;

	s = nvm->stor;
	if (!s)
		return;

	if (s->gc_ops->exit)
		s->gc_ops->exit(s);

	if (s->type->exit)
		s->type->exit(s);

	del_timer(&s->gc_timer);

	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_pools_free(s);

	vfree(s->trans_map);
	vfree(s->rev_trans_map);

	mempool_destroy(s->page_pool);
	mempool_destroy(s->addr_pool);

	percpu_ida_destroy(&s->free_inflight);

	kfree(s);

	kmem_cache_destroy(_addr_cache);

	pr_info("lightnvm: successfully unloaded\n");
}
EXPORT_SYMBOL_GPL(nvm_exit);

MODULE_DESCRIPTION("LightNVM");
MODULE_AUTHOR("Matias Bjorling <mabj@itu.dk>");
MODULE_LICENSE("GPL");
