/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Google LLC
 */

#ifndef _CASFS_DIGEST_H_
#define _CASFS_DIGEST_H_

#include <linux/rhashtable.h>
#include "hash.h"

#define CASFS_SHA256_LEN 32

/*
 * Per-mount map from a blob's git hash to the SHA-256 of its content, so
 * build tools can read a file's digest from the sha256 xattr instead of
 * hashing it. User space loads known digests with CASFS_IOC_ADD_DIGESTS;
 * snapshots of modified files add theirs once the table is active.
 */
struct cas_digest_table {
	struct rhashtable ht;
	bool ready;
	/* Set once digests are in use; snapshots then also compute SHA-256. */
	bool active;
	atomic_t count;
};

int cas_digest_table_init(struct cas_digest_table *table);
void cas_digest_table_destroy(struct cas_digest_table *table);

static inline bool cas_digest_table_active(const struct cas_digest_table *table)
{
	return READ_ONCE(table->active);
}

static inline void cas_digest_table_activate(struct cas_digest_table *table)
{
	if (!READ_ONCE(table->active))
		WRITE_ONCE(table->active, true);
}

/* Records the digest of hash; an existing entry for hash is kept. */
int cas_digest_put(struct cas_digest_table *table, const struct cas_hash *hash,
		   const u8 *sha256);

/* Copies the digest of hash into sha256 and returns true if it is known. */
bool cas_digest_get(struct cas_digest_table *table, const struct cas_hash *hash,
		    u8 *sha256);

#endif // _CASFS_DIGEST_H_
