#include <linux/lightnvm.h>
#include "nvm.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

struct greedy_data {
	struct list_head prio_list;		/* Blocks that may be GC'ed */
};

static inline struct greedy_data *greedy_data(struct nvm_pool *pool)
{
	return (struct greedy_data *)pool->gc_private;
}

static void queue_pool_gc(struct nvm_pool *pool)
{
	struct nvm_stor *s = pool->s;

	queue_work(s->krqd_wq, &pool->ws_gc);
}

void nvm_gc_cb(unsigned long data)
{
	struct nvm_stor *s = (struct nvm_stor *)data;
	struct nvm_pool *pool;
	int i;

	nvm_for_each_pool(s, pool, i)
		queue_pool_gc(pool);

	mod_timer(&s->gc_timer,
			jiffies + msecs_to_jiffies(s->config.gc_time));
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct nvm_block *block_max_invalid(struct nvm_block *a,
					   struct nvm_block *b)
{
	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return a;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? b : a;
}

/* linearly find the block with highest number of invalid pages
 * requires pool->lock */
static struct nvm_block *block_prio_find_max(struct nvm_pool *pool)
{
	struct greedy_data *gc_data = greedy_data(pool);
	struct list_head *prio_list = &gc_data->prio_list;
	struct nvm_block *block, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct nvm_block, prio);
	list_for_each_entry(block, prio_list, prio)
		max = block_max_invalid(max, block);

	return max;
}

/* Move data away from flash block to be erased. Additionally update the
 * l to p and p to l mappings. */
static void nvm_move_valid_pages(struct nvm_stor *s, struct nvm_block *block)
{
	struct nvm_dev *dev = s->dev;
	struct request_queue *q = dev->q;
	struct nvm_addr src;
	struct nvm_rev_addr *rev;
	struct bio *src_bio;
	struct request *src_rq, *dst_rq = NULL;
	struct page *page;
	int slot;
	DECLARE_COMPLETION(sync);

	if (bitmap_full(block->invalid_pages, s->nr_pages_per_blk))
		return;

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   s->nr_pages_per_blk)) <
						s->nr_pages_per_blk) {
		/* Perform read */
		src.addr = block_to_addr(block) + slot;
		src.block = block;

		BUG_ON(src.addr >= s->nr_pages);

		src_bio = bio_alloc(GFP_NOIO, 1);
		if (!src_bio) {
			pr_err("nvm: failed to alloc gc bio request");
			break;
		}
		src_bio->bi_iter.bi_sector = src.addr * NR_PHY_IN_LOG;
		page = mempool_alloc(s->page_pool, GFP_NOIO);

		/* TODO: may fail whem EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, src_bio, page, EXPOSED_PAGE_SIZE, 0);

		src_rq = blk_mq_alloc_request(q, READ, GFP_KERNEL, false);
		if (!src_rq) {
			mempool_free(page, s->page_pool);
			pr_err("nvm: failed to alloc gc request");
			break;
		}

		blk_init_request_from_bio(src_rq, src_bio);

		/* We take the reverse lock here, and make sure that we only
		 * release it when we have locked its logical address. If
		 * another write on the same logical address is
		 * occuring, we just let it stall the pipeline.
		 *
		 * We do this for both the read and write. Fixing it after each
		 * IO.
		 */
		spin_lock(&s->rev_lock);
		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		rev = &s->rev_trans_map[src.addr];

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		/* unlocked by nvm_submit_bio nvm_endio */
		__nvm_lock_laddr_range(s, 1, rev->addr, 1);
		spin_unlock(&s->rev_lock);

		nvm_setup_rq(s, src_rq, &src, rev->addr, NVM_RQ_GC);
		blk_execute_rq(q, dev->disk, src_rq, 0);
		blk_put_request(src_rq);

		dst_rq = blk_mq_alloc_request(q, WRITE, GFP_KERNEL, false);
		blk_init_request_from_bio(dst_rq, src_bio);

		/* ok, now fix the write and make sure that it haven't been
		 * moved in the meantime. */
		spin_lock(&s->rev_lock);

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		src_bio->bi_iter.bi_sector = rev->addr * NR_PHY_IN_LOG;

		/* again, unlocked by nvm_endio */
		__nvm_lock_laddr_range(s, 1, rev->addr, 1);

		spin_unlock(&s->rev_lock);

		__nvm_write_rq(s, dst_rq, 1);
		blk_execute_rq(q, dev->disk, dst_rq, 0);

overwritten:
		blk_put_request(dst_rq);
		bio_put(src_bio);
		mempool_free(page, s->page_pool);
	}

	WARN_ON(!bitmap_full(block->invalid_pages, s->nr_pages_per_blk));
}

static void nvm_greedy_collect(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, ws_gc);
	struct greedy_data *gc_data = greedy_data(pool);
	struct list_head *prio_list = &gc_data->prio_list;
	struct nvm_stor *s = pool->s;
	struct nvm_block *block;
	unsigned int nr_blocks_need;
	unsigned long flags;

	nr_blocks_need = pool->nr_blocks / GC_LIMIT_INVERSE;

	if (nr_blocks_need < s->nr_aps)
		nr_blocks_need = s->nr_aps;

	local_irq_save(flags);
	spin_lock(&pool->lock);
	while (nr_blocks_need > pool->nr_free_blocks &&
						!list_empty(prio_list)) {
		block = block_prio_find_max(pool);

		if (!block->nr_invalid_pages) {
			pr_err("No invalid pages");
			break;
		}

		list_del_init(&block->prio);

		BUG_ON(!block_is_full(block));
		BUG_ON(atomic_inc_return(&block->gc_running) != 1);

		queue_work(s->kgc_wq, &block->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&pool->lock);
	local_irq_restore(flags);

	/* TODO: Hint that request queue can be started again */
}

void nvm_gc_block(struct work_struct *work)
{
	struct nvm_block *block = container_of(work, struct nvm_block, ws_gc);
	struct nvm_stor *s = block->pool->s;

	/* TODO: move outside lock to allow multiple pages
	 * in parallel to be erased. */
	nvm_move_valid_pages(s, block);
	nvm_erase_block(s, block);
	s->type->pool_put_blk(block);
}

/*nvm_gc_recycle_block*/
void nvm_gc_recycle_block(struct work_struct *work)
{
	struct nvm_block *block = container_of(work, struct nvm_block, ws_eio);
	struct nvm_pool *pool = block->pool;
	struct greedy_data *gc_data = greedy_data(pool);

	spin_lock(&pool->lock);
	list_add_tail(&block->prio, &gc_data->prio_list);
	spin_unlock(&pool->lock);
}

void nvm_gc_kick(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	unsigned int i;

	BUG_ON(!s);

	nvm_for_each_pool(s, pool, i)
		queue_pool_gc(pool);
}

static void nvm_greedy_queue(struct nvm_block *b)
{
	/*Consider block reclaim-able, add to relevant data structures for future GC'ing*/
}

static void nvm_greedy_reclaim(struct nvm_block *b)
{
	/*Block has been selected as victim, migrate live data and GC*/
}

static int nvm_gc_init(struct nvm_stor *s)
{
	/*set s->gc_private if need be*/
	struct nvm_pool *pool;
	struct greedy_data *pool_data;
	int i;

	pool_data = kcalloc(s->nr_pools, sizeof(struct greedy_data),
						GFP_KERNEL);
	if (!pool_data)
		goto alloc_err;

	nvm_for_each_pool(s, pool, i) {
		struct greedy_data *gc_data = &pool_data[i];
		INIT_WORK(&pool->ws_gc, nvm_greedy_collect);
		pool->gc_private = gc_data;
		INIT_LIST_HEAD(&gc_data->prio_list);
	}

	return 0;
alloc_err:
	return -1;
}

static void nvm_gc_exit(struct nvm_stor *s)
{
	/*All per-pool GC-data space was allocated in one go, so this suffices*/
	kfree(s->pools[0].gc_private);
}

struct nvm_gc_type nvm_gc_greedy = {
	.name 		= "greedy",
	.version 	= {1, 0, 0},

	.on_gc_time	= nvm_gc_cb,
	.queue		= nvm_greedy_queue,
	.reclaim	= nvm_greedy_reclaim,
	.kick		= nvm_gc_kick,

	.init		= nvm_gc_init,
	.exit		= nvm_gc_exit,
};
