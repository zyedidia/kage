// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/kage.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <crypto/internal/hash.h>

#include "proc.h"
#include "guards.h"

struct kage_shash {
	struct shash_alg alg;
	struct kage *kage;

	unsigned long g_alg;
	unsigned long g_setkey, g_init, g_update, g_final;
	unsigned int ctxsize;
	unsigned int descsize;
	unsigned int digestsize;

	struct list_head node;
};

static LIST_HEAD(kage_shashes);
static DEFINE_SPINLOCK(kage_lock);

static bool ptr_in_guest(struct kage *kage, unsigned long ptr)
{
	return (ptr - kage->base) < KAGE_GUEST_SIZE;
}

/* Recover the shadow from a tfm: the core allocated the tfm against our
 * shadow's base alg, so crypto_shash_alg(tfm) == &sh->alg. */
static struct kage_shash *shadow_of(struct crypto_shash *tfm)
{
	return container_of(crypto_shash_alg(tfm), struct kage_shash, alg);
}

static int kage_shash_setkey(struct crypto_shash *tfm, const u8 *key,
			     unsigned int keylen)
{
	struct kage_shash *sh = shadow_of(tfm);
	struct kage *kage = sh->kage;
	void *host_ctx = crypto_shash_ctx(tfm);
	size_t coff = (u8 *)host_ctx - (u8 *)tfm;
	void *g_tfm = NULL, *g_key = NULL;
	int rv;

	g_tfm = kage_memory_alloc(kage, coff + sh->ctxsize, MOD_DATA, GFP_KERNEL);
	g_key = keylen ? kage_memory_alloc(kage, keylen, MOD_DATA, GFP_KERNEL)
		       : NULL;
	if (!g_tfm || (keylen && !g_key)) {
		rv = -ENOMEM;
		goto out;
	}
	if (keylen)
		memcpy(g_key, key, keylen);

	rv = (int)kage_call(kage, (void *)sh->g_setkey,
			    (unsigned long)g_tfm, (unsigned long)g_key,
			    keylen, 0, 0, 0);

	/* setkey wrote the key schedule into the guest tfm ctx. Copy it back
	 * to the host tfm ctx, where init() will read it. */
	if (rv == 0)
		memcpy(host_ctx, (u8 *)g_tfm + coff, sh->ctxsize);
out:
	if (g_key)
		kage_memory_free(kage, g_key);
	if (g_tfm)
		kage_memory_free(kage, g_tfm);
	return rv;
}

static int kage_shash_init(struct shash_desc *desc)
{
	struct kage_shash *sh = shadow_of(desc->tfm);
	struct kage *kage = sh->kage;
	void *host_tctx = crypto_shash_ctx(desc->tfm);
	size_t coff = (u8 *)host_tctx - (u8 *)desc->tfm;
	size_t doff = offsetof(struct shash_desc, __ctx);
	void *g_tfm = NULL, *g_desc = NULL;
	int rv;

	g_tfm = kage_memory_alloc(kage, coff + sh->ctxsize, MOD_DATA, GFP_KERNEL);
	g_desc = kage_memory_alloc(kage, doff + sh->descsize, MOD_DATA, GFP_KERNEL);
	if (!g_tfm || !g_desc) {
		rv = -ENOMEM;
		goto out;
	}
	/* init() reads the key schedule out of desc->tfm's ctx. */
	memcpy((u8 *)g_tfm + coff, host_tctx, sh->ctxsize);
	((struct shash_desc *)g_desc)->tfm = (struct crypto_shash *)g_tfm;

	rv = (int)kage_call(kage, (void *)sh->g_init,
			    (unsigned long)g_desc, 0, 0, 0, 0, 0);
	if (rv == 0)
		memcpy(shash_desc_ctx(desc), (u8 *)g_desc + doff, sh->descsize);
out:
	if (g_desc)
		kage_memory_free(kage, g_desc);
	if (g_tfm)
		kage_memory_free(kage, g_tfm);
	return rv;
}

static int kage_shash_update(struct shash_desc *desc, const u8 *data,
			     unsigned int len)
{
	struct kage_shash *sh = shadow_of(desc->tfm);
	struct kage *kage = sh->kage;
	size_t doff = offsetof(struct shash_desc, __ctx);
	void *g_desc = NULL, *g_data = NULL;
	int rv;

	g_desc = kage_memory_alloc(kage, doff + sh->descsize, MOD_DATA, GFP_KERNEL);
	if (!g_desc) {
		rv = -ENOMEM;
		goto out;
	}
	if (len) {
		g_data = kage_memory_alloc(kage, len, MOD_DATA, GFP_KERNEL);
		if (!g_data) {
			rv = -ENOMEM;
			goto out;
		}
		memcpy(g_data, data, len);
	}
	memcpy((u8 *)g_desc + doff, shash_desc_ctx(desc), sh->descsize);
	((struct shash_desc *)g_desc)->tfm = NULL;

	rv = (int)kage_call(kage, (void *)sh->g_update,
			    (unsigned long)g_desc, (unsigned long)g_data,
			    len, 0, 0, 0);
	if (rv == 0)
		memcpy(shash_desc_ctx(desc), (u8 *)g_desc + doff, sh->descsize);
out:
	if (g_data)
		kage_memory_free(kage, g_data);
	if (g_desc)
		kage_memory_free(kage, g_desc);
	return rv;
}

static int kage_shash_final(struct shash_desc *desc, u8 *out)
{
	struct kage_shash *sh = shadow_of(desc->tfm);
	struct kage *kage = sh->kage;
	size_t doff = offsetof(struct shash_desc, __ctx);
	void *g_desc = NULL, *g_out = NULL;
	int rv;

	g_desc = kage_memory_alloc(kage, doff + sh->descsize, MOD_DATA, GFP_KERNEL);
	g_out = kage_memory_alloc(kage, sh->digestsize, MOD_DATA, GFP_KERNEL);
	if (!g_desc || !g_out) {
		rv = -ENOMEM;
		goto out;
	}
	memcpy((u8 *)g_desc + doff, shash_desc_ctx(desc), sh->descsize);
	((struct shash_desc *)g_desc)->tfm = NULL;

	rv = (int)kage_call(kage, (void *)sh->g_final,
			    (unsigned long)g_desc, (unsigned long)g_out,
			    0, 0, 0, 0);
	if (rv == 0)
		memcpy(out, g_out, sh->digestsize);
out:
	if (g_out)
		kage_memory_free(kage, g_out);
	if (g_desc)
		kage_memory_free(kage, g_desc);
	return rv;
}

/*
 * Our marshalling only handles a subset of the shash contract. Return a reason
 * if an alg needs anything beyond what we support.
 */
static const char *kage_shash_unsupported(const struct shash_alg *a)
{
	if (!a->init || !a->update || !a->final)
		return "missing init/update/final op";
	if (a->base.cra_flags & CRYPTO_AHASH_ALG_BLOCK_ONLY)
		return "block-only alg (core buffers partial blocks)";
	if (a->init_tfm || a->exit_tfm || a->clone_tfm ||
	    a->base.cra_init || a->base.cra_exit)
		return "per-tfm lifecycle hooks";
	if (a->export || a->import || a->export_core || a->import_core)
		return "custom export/import (state is not a flat ctx copy)";
	if (a->statesize && a->statesize != a->descsize)
		return "statesize != descsize";
	return NULL;
}

int guard_crypto_register_shash(struct kage_proc *proc,
				struct kage_g2h_call *call,
				unsigned long g_alg_ptr)
{
	struct kage *kage = proc->kage;
	struct shash_alg *g_alg = (struct shash_alg *)g_alg_ptr;
	struct kage_shash *sh;
	const char *reason;
	int rv;

	if (!ptr_in_guest(kage, g_alg_ptr))
		return -EINVAL;

	reason = kage_shash_unsupported(g_alg);
	if (reason) {
		pr_err("kage: shash '%s': unsupported (%s)\n",
		       g_alg->base.cra_driver_name, reason);
		return -EOPNOTSUPP;
	}

	sh = kzalloc(sizeof(*sh), GFP_KERNEL);
	if (!sh)
		return -ENOMEM;

	sh->kage = kage;
	sh->g_alg = g_alg_ptr;
	sh->g_setkey = (unsigned long)g_alg->setkey;
	sh->g_init = (unsigned long)g_alg->init;
	sh->g_update = (unsigned long)g_alg->update;
	sh->g_final = (unsigned long)g_alg->final;

	sh->ctxsize = g_alg->base.cra_ctxsize;
	sh->descsize = g_alg->descsize;
	sh->digestsize = g_alg->digestsize;

	sh->alg.digestsize = sh->digestsize;
	sh->alg.descsize = sh->descsize;
	sh->alg.setkey = sh->g_setkey ? kage_shash_setkey : NULL;
	sh->alg.init = kage_shash_init;
	sh->alg.update = kage_shash_update;
	sh->alg.final = kage_shash_final;
	sh->alg.base.cra_blocksize = g_alg->base.cra_blocksize;
	sh->alg.base.cra_ctxsize = sh->ctxsize;
	sh->alg.base.cra_priority = g_alg->base.cra_priority;
	strscpy(sh->alg.base.cra_name, g_alg->base.cra_name,
		sizeof(sh->alg.base.cra_name));
	strscpy(sh->alg.base.cra_driver_name, g_alg->base.cra_driver_name,
		sizeof(sh->alg.base.cra_driver_name));
	sh->alg.base.cra_module = NULL; /* FIXME: refcount the guest module */

	pr_info("kage: shadow shash '%s' (driver '%s') ctxsize=%u descsize=%u digestsize=%u\n",
		sh->alg.base.cra_name, sh->alg.base.cra_driver_name,
		sh->ctxsize, sh->descsize, sh->digestsize);

	rv = crypto_register_shash(&sh->alg);
	if (rv) {
		pr_err("kage: crypto_register_shash(shadow) failed: %d\n", rv);
		kfree(sh);
		return rv;
	}

	spin_lock(&kage_lock);
	list_add(&sh->node, &kage_shashes);
	spin_unlock(&kage_lock);
	return 0;
}

int guard_crypto_unregister_shash(struct kage_proc *proc,
				  struct kage_g2h_call *call,
				  unsigned long g_alg_ptr)
{
	struct kage_shash *sh = NULL, *it;

	spin_lock(&kage_lock);
	list_for_each_entry(it, &kage_shashes, node) {
		if (it->kage == proc->kage && it->g_alg == g_alg_ptr) {
			sh = it;
			list_del(&sh->node);
			break;
		}
	}
	spin_unlock(&kage_lock);

	if (!sh) {
		pr_err("kage: crypto_unregister_shash: no shadow for 0x%lx\n",
		       g_alg_ptr);
		return 0;
	}

	crypto_unregister_shash(&sh->alg);
	kfree(sh);
	return 0;
}
