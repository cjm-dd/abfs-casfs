// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Google LLC
 */

#include <linux/slab.h>
#include <linux/rhashtable.h>
#include "digest.h"

struct cas_digest_entry {
	struct rhash_head node;
	struct cas_hash hash;
	u8 sha256[CASFS_SHA256_LEN];
};

static const struct rhashtable_params cas_digest_params = {
	.key_len = sizeof(struct cas_hash),
	.key_offset = offsetof(struct cas_digest_entry, hash),
	.head_offset = offsetof(struct cas_digest_entry, node),
	/*
	 * Sized for one checkout's digests up front, so the first bulk load
	 * does not resize through atomic allocations: this hint gives 65536
	 * buckets, room for 49152 entries. Past max_size inserts fail, which
	 * only makes the xattr return ENODATA for those files.
	 */
	.nelem_hint = 32768,
	.max_size = 1u << 22,
	.automatic_shrinking = false,
};

int cas_digest_table_init(struct cas_digest_table *table)
{
	int err;

	table->active = false;
	atomic_set(&table->count, 0);
	err = rhashtable_init(&table->ht, &cas_digest_params);
	table->ready = !err;
	return err;
}

static void cas_digest_free(void *ptr, void *arg)
{
	kfree(ptr);
}

void cas_digest_table_destroy(struct cas_digest_table *table)
{
	if (!table->ready)
		return;
	/* Called once the mount has no readers left. */
	rhashtable_free_and_destroy(&table->ht, cas_digest_free, NULL);
	table->ready = false;
}

int cas_digest_put(struct cas_digest_table *table, const struct cas_hash *hash,
		   const u8 *sha256)
{
	struct cas_digest_entry *entry;
	int err;

	if (unlikely(!table->ready))
		return -ENODEV;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (unlikely(!entry))
		return -ENOMEM;

	entry->hash = *hash;
	memcpy(entry->sha256, sha256, CASFS_SHA256_LEN);

	err = rhashtable_lookup_insert_fast(&table->ht, &entry->node,
					    cas_digest_params);
	if (err) {
		kfree(entry);
		return err == -EEXIST ? 0 : err;
	}
	atomic_inc(&table->count);
	return 0;
}

bool cas_digest_get(struct cas_digest_table *table, const struct cas_hash *hash,
		    u8 *sha256)
{
	struct cas_digest_entry *entry;
	bool found = false;

	if (unlikely(!table->ready))
		return false;

	rcu_read_lock();
	entry = rhashtable_lookup(&table->ht, hash, cas_digest_params);
	if (entry) {
		memcpy(sha256, entry->sha256, CASFS_SHA256_LEN);
		found = true;
	}
	rcu_read_unlock();
	return found;
}
