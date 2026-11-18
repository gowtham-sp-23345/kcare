#include <linux/printk.h>
#include <linux/elf.h>
#include <linux/version.h>

#include <asm/debug-monitors.h>
#include <asm/elf.h>
#include <asm/errno.h>
#include <asm/cacheflush.h>

#include <kcare/kcare_file.h>

#include "kcare.h"

extern struct kpatch_context kpatch_ctx;

enum aarch64_reloc_op {
	RELOC_OP_NONE,
	RELOC_OP_ABS,
	RELOC_OP_PREL,
	RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, __le32 *place, u64 val)
{
	switch (reloc_op) {
	case RELOC_OP_ABS:
		return val;
	case RELOC_OP_PREL:
		return val - (u64)place;
	case RELOC_OP_PAGE:
		return (val & ~0xfff) - ((u64)place & ~0xfff);
	case RELOC_OP_NONE:
		return 0;
	}

	pr_err("do_reloc: unknown relocation operation %d\n", reloc_op);
	return 0;
}

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
	s64 sval = do_reloc(op, place, val);

	switch (len) {
	case 16:
		*(s16 *)place = sval;
		if (sval < S16_MIN || sval > U16_MAX)
			return -ERANGE;
		break;
	case 32:
		*(s32 *)place = sval;
		if (sval < S32_MIN || sval > U32_MAX)
			return -ERANGE;
		break;
	case 64:
		*(s64 *)place = sval;
		break;
	default:
		pr_err("Invalid length (%d) for data relocation\n", len);
		return 0;
	}
	return 0;
}

static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5


static u32 kcare_aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
					       u32 insn, u64 imm)
{
	u32 immlo, immhi, mask;
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
		imm >>= ADR_IMM_HILOSPLIT;
		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
		imm = immlo | immhi;
		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("aarch64_insn_encode_immediate: unknown immediate encoding %d\n",
			       type);
			return AARCH64_BREAK_FAULT;
		}
	}

	/* Update the immediate field. */
	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}


static int reloc_insn_imm(enum aarch64_reloc_op op, __le32 *place, u64 val,
			  int lsb, int len, enum aarch64_insn_imm_type imm_type)
{
	u64 imm, imm_mask;
	s64 sval;
	u32 insn = le32_to_cpu(*place);

	/* Calculate the relocation value. */
	sval = do_reloc(op, place, val);
	sval >>= lsb;

	/* Extract the value bits and shift them to bit 0. */
	imm_mask = (BIT(lsb + len) - 1) >> lsb;
	imm = sval & imm_mask;

	/* Update the instruction's immediate field. */
	insn = kcare_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*place = cpu_to_le32(insn);

	/*
	 * Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0.
	 */
	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

	/*
	 * Overflow has occurred if the upper bits are not all equal to
	 * the sign bit of the value.
	 */
	if ((u64)(sval + 1) >= 2)
		return -ERANGE;

	return 0;
}

static const char *rel_type(Elf64_Xword type)
{
	static const char *ret = "<unknown>";
	static char buf[128];
	static const char *type_name[] = {
#define REL_TYPE(X) [X] = #X
		REL_TYPE(R_AARCH64_NONE),
		REL_TYPE(R_AARCH64_ABS64),
		REL_TYPE(R_AARCH64_PREL32),
		REL_TYPE(R_AARCH64_PREL64),
		REL_TYPE(R_AARCH64_ADR_PREL_PG_HI21),
		REL_TYPE(R_AARCH64_ADR_PREL_PG_HI21_NC),
		REL_TYPE(R_AARCH64_ADD_ABS_LO12_NC),
		REL_TYPE(R_AARCH64_CALL26),
		REL_TYPE(R_AARCH64_LDST8_ABS_LO12_NC),
		REL_TYPE(R_AARCH64_JUMP26),
		REL_TYPE(R_AARCH64_LDST32_ABS_LO12_NC),
		REL_TYPE(R_AARCH64_LDST64_ABS_LO12_NC),
#undef REL_TYPE
	};

	if (type < sizeof(type_name) / sizeof(type_name[0]) && type_name[type])
		return type_name[type];

	sprintf(buf, "%s(%llu)", ret, type);
	return buf;
}

static int kpatch_apply_relocations_extra(struct kpatch_file *file, long delta)
{
	struct kpatch_reloc *rel = (void *) file + file->rel_offset +
				sizeof(struct kpatch_reloc) * file->nr_reloc;
	struct kpatch_reloc *rel_last = (void *) file + file->kpatch_offset;
	long kpatch_code = (long)rel_last;
	long val, addend;
	void *loc;
	int ovf = -ERANGE, i, err = 0;

	i = ((long)rel_last - (long)rel) / sizeof(struct kpatch_reloc);
	printk(KERN_DEBUG "kcare: %d extra relocations to fixup...\n", i);
	for (i = 0; rel < rel_last; ++rel, ++i) {
		uint64_t before;
		bool overflow_check = true;

		loc = (void *) file + file->kpatch_offset + rel->offset;
		switch (rel->pcrel) {
		case KPATCH_PCREL_EXT_VMLINUX:
		case KPATCH_PCREL_EXT_PER_CPU:
			addend = delta;
			break;
		case KPATCH_PCREL_EXT_KPATCH:
			addend = kpatch_code;
			break;
		default:
			printk(KERN_ERR "rel[%d] unknown pcrel type %d\n", i, rel->pcrel);
			err = 1;
			continue;
		}

		val = rel->value + addend;

		before = *(uint64_t *)loc;

		switch (reloc_get_type(rel)) {
		case R_AARCH64_NONE:
			break;
		case R_AARCH64_PREL32:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
			break;
		case R_AARCH64_PREL64:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
			break;
		case R_AARCH64_ABS64:
			overflow_check = false;
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
			break;
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			overflow_check = false;
			break;
		case R_AARCH64_ADR_PREL_PG_HI21:
			ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21,
					     AARCH64_INSN_IMM_ADR);
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST32_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10,
					     AARCH64_INSN_IMM_12);
			break;
		case R_AARCH64_LDST64_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9,
					     AARCH64_INSN_IMM_12);
			break;

		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26,
					     AARCH64_INSN_IMM_26);

			if (ovf == -ERANGE) {
				printk(KERN_ERR "rel[%d] val = %lx is too far\n",
				       i, val);
				err = 1;
			}

#if 0
			if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
			    ovf == -ERANGE) {
				val = module_emit_plt_entry(me, loc, &rel[i], sym);
				ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2,
						     26, AARCH64_INSN_IMM_26);
			}
#endif
			break;
		default:
			printk(KERN_ERR "rel[%d] unknown type = %d\n", i, reloc_get_type(rel));
			err = 1;
			continue;
		}

		if (kpatch_ctx.kmod_data.debug) {
			printk(KERN_DEBUG
			       "rel[%d], pcrel %d, type %s, offset = %08x, loc = %px, value = %x, addend = %lx, val = %lx, before = %016llx, after=%016llx\n",
			       i, rel->pcrel, rel_type(reloc_get_type(rel)), rel->offset, loc,
			       rel->value, addend, val, before, *(uint64_t *)loc);
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
		caches_clean_inval_pou((long)loc, (long)loc + sizeof(long));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
		__flush_icache_range((long)loc,  (long)loc + sizeof(long));
#else
		flush_icache_range((long)loc,  (long)loc + sizeof(long));
#endif

		if (overflow_check && ovf == -ERANGE) {
			printk(KERN_ERR "kcare: overflow in a relocation %d\n", i);
			err = 1;
			break;
		}
	}

	if (err) {
		if (!ovf)
			ovf = -ENOTSUPP;
		goto err;
	}
	ovf = 0;
err:
	printk(KERN_DEBUG "kcare: fixed %d extra relocations\n", i);
	return ovf;
}

int kcare_apply_relocations(struct kpatch_file *file, long delta)
{
	if (file->nr_reloc != 0) {
		printk(KERN_INFO "kcare: wrong relocations for ARM64\n");
		return -EINVAL;
	}

	return kpatch_apply_relocations_extra(file, delta);
}
