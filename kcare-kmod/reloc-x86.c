#include <linux/kernel.h>
#include <linux/elf.h>
#include <linux/version.h>

#include <asm/elf.h>
#include <asm/errno.h>

#include <kcare/kcare_file.h>

#include "kcare.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#define VMLINUX_LINK_ADDRESS (0xffffffff80000000ul + 0x1000000)
#else
#ifdef CONFIG_X86_32
#define VMLINUX_LINK_ADDRESS (0xc0000000 + 0x400000)
#else
#ifdef CONFIG_X86_64_XEN
#define VMLINUX_LINK_ADDRESS (0xffffffff80200000ul)
#else
#define VMLINUX_LINK_ADDRESS (0xffffffff80000000ul)
#endif
#endif
#endif

static int kpatch_apply_relocations_extra(struct kpatch_file *file, long delta)
{
	struct kpatch_reloc *rel = (void *) file + file->rel_offset +
				sizeof(struct kpatch_reloc) * file->nr_reloc;
	struct kpatch_reloc *rel_last = (void *) file + file->kpatch_offset;
	long kpatch_code = (long)rel_last;
	long val, addend;
	void *loc;
	int ret = -EOVERFLOW, i;

	i = ((long)rel_last - (long)rel) / sizeof(struct kpatch_reloc);
	printk(KERN_DEBUG "kcare: %d extra relocations to fixup...\n", i);
	for (i = 0; rel < rel_last; ++rel, ++i) {
		loc = (void *) file + file->kpatch_offset + rel->offset;
		addend = rel->pcrel == KPATCH_PCREL_EXT_PER_CPU ? 0 :
			(rel->pcrel == KPATCH_PCREL_EXT_VMLINUX ? delta : kpatch_code);

		switch (reloc_get_type(rel)) {
			case R_X86_64_64:
				*(u64 *) loc += addend;
				break;
			case R_X86_64_32S:
				val = *(s32 *) loc;
				val += addend;
				*(s32 *) loc = val;
				if (val != *(s32 *) loc)
					goto err;
				break;
			case R_X86_64_32:
				val = *(u32 *) loc;
				val += addend;
				if (val & ~0xfffffffful)
					goto err;
				*(u32 *) loc = val;
				break;
			case R_X86_64_PC32:
			case R_X86_64_PLT32:
				val = *(s32 *) loc;
				val += addend;
				val -= (u64) loc;
				*(s32 *) loc = val;
				break;
#ifdef R_X86_64_PC64
			case R_X86_64_PC64:
				val = *(s64 *) loc;
				val += addend;
				val -= (u64) loc;
				*(s64 *) loc = val;
				break;
#endif
			default:
				ret = -EINVAL;
				goto err;
		}
	}
	ret = 0;
err:
	printk(KERN_DEBUG "kcare: fixed %d extra relocations\n", i);
	return ret;
}

int kcare_apply_relocations(struct kpatch_file *file, long delta)
{
	int i;
	char *raw = (char *)file;
	uint32_t *ptr;
	struct kpatch_reloc *reloc = (struct kpatch_reloc *)(raw + file->rel_offset);

	/* delta is 64-bit offset, we only need 32-bit here */
	delta = delta & UINT_MAX;

	printk(KERN_DEBUG "kcare: %d relocations to fixup...\n", file->nr_reloc);
	for (i = 0; i < file->nr_reloc; i++) {
		ptr = (uint32_t *)(raw + file->kpatch_offset + reloc[i].offset);
		if (reloc[i].pcrel)
			*ptr = VMLINUX_LINK_ADDRESS + *ptr -
				file->kpatch_offset - (uint32_t)(long)raw;
		else
			*ptr = *ptr + file->kpatch_offset + (uint32_t)(long)raw;
	}
	printk(KERN_DEBUG "kcare: fixed %d relocations\n", i);

	return kpatch_apply_relocations_extra(file, delta);
}
