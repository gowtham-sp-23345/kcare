#ifndef __KCARE_FILE_H__
#define __KCARE_FILE_H__

#define MOD_STR_LEN_SCANF 63
#define MOD_STR_LEN (MOD_STR_LEN_SCANF + 1)

typedef uint32_t kpatch_offset_t;
typedef uint32_t kpatch_reloc_t;

#define KPATCH_DEFAULT_WAIT_PERIOD_SEC 300U /* 5 minutes */
#define KPATCH_DEFAULT_RETRIES_NUM 40U

/* Load patch into memory, verifies it (checksum, etc...) and applies it */
#define KPATCH_APPLY      _IOW('k', 0, struct kpatch_payload *)
/* Undo the patch */
#define KPATCH_UNDO      _IO('k', 1)
/* Query info about patches */
#define KPATCH_INFO      _IOR('k', 2, struct kpatch_query *)
#define KPATCH_REPORT    _IOR('k', 3, char *)

struct kpatch_file;
struct kpatch_undo;

/*
 * Fixup and regular patch have different entry point prototypes. Fixup would receive a pointer to
 * struct kpatch_undo for already applied patch.
 */
#ifdef CONFIG_KPATCH_SECOND
typedef int (*kpatch_entry)(struct kpatch_file *, unsigned long size, void **, struct kpatch_undo *);
#else
typedef int (*kpatch_entry)(struct kpatch_file *, unsigned long size, void **);
#endif
typedef int (*kpatch_undo_patch)(struct kpatch_undo *);
typedef unsigned long (*kpatch_name_lookup)(const char *);

#define KPATCH_FILE_MAGIC1	"KPATCH1"
/*
 * ABI version, should be changed each time, when kpatch_file,  kpatch_info or
 * kpatch_reloc is changed.
 *
 * History of changes:
 * 0x0001 - initial version
 * 0x0002 - KPATCH_PCREL_EXT_PER_CPU was changed and reverted, however few releases
 *          was made with modified value(update-2021-02-24-1, update-2021-02-25-1 and
 *          update-2021-02-25-2). We are forced to bump abiver to prevent crashes on
 *          systems that loaded kmod from those updates and try to load patch with
 *          alternative value of KPATCH_PCREL_EXT_PER_CPU.
 *        - kpatch_delta entry cannot be zero anymore
 * 0x0003 - patching/unpatching attempts count becomes customizable, however few releases
 *          was made with new ABI in core.c and old one in kcare_main.c
 *          It leads to fake applying patch inasmuch as kpatch_retries is zero.
 *          We are forced to bump abiver to prevent fake patching.
 * 0x0004 - crashreporter release compatibility.
 * 0x0005 - Added individual module fault injection
 * 0x0007 - Removed kpatch_module_alloc from kpatch_offset_t entries.
 * 0x0008 - Removed deprecated kpatch_mds_test.
 * 0x0009 - Added sharing of gcov data.
 * 0x000a - Reference kpatch_context to access all kpatch related data exported
 *          by kcare module.
 *
 * WARNING: Always bump MODULE_VERSION together with KPATCH_ABI_VERSION.
 */

#define KPATCH_ABI_VERSION	0x000a
#define KPATCH_MAX_NR_ENTRIES	16
#define KPATCH_UNAME_LEN	256

#define KPATCH_DEBUG_FLAG    0
#define KPATCH_NOFREEZE_FLAG 1 /* this flag is ignored, use safety method insted */

enum {
	KPATCH_SAFETY_METHOD_DEFAULT = 0,
	KPATCH_SAFETY_METHOD_FREEZE_ALL,
	KPATCH_SAFETY_METHOD_FREEZE_NONE,
	KPATCH_SAFETY_METHOD_FREEZE_CONFLICT,
	KPATCH_SAFETY_METHOD_MAX,
};

struct kpatch_payload {
	size_t size;
	char *patch;
	char *description; // could be NULL
};

struct kpatch_file {
	char magic[8];			/* magic string */
	unsigned char flags;
	unsigned char safety_method;
	uint16_t abiver;		/* ABI version, a temp solution to distinct
					   various kpatch_file, kpatch_info and
					   kpatch_reloc layouts. Should be equal to
					   KPATCH_ABI_VER. */

	uint32_t reserved_for_abicrc;	/* four bytes reserved for ABI CRC32.
					   A checksum that should be calculated from
					   struct kpatch_file, struct kpatch_info and
					   struct kpatch_reloc definitions. */

	char modulename[MOD_STR_LEN];	/* "vmlinux" or module name */
	char uname[KPATCH_UNAME_LEN];	/* /proc/version of the kernel */

	uint64_t build_time;		/* build time */
	uint32_t csum;			/* checksum of the whole kpatch */
	uint32_t nr_reloc;		/* number of relocations */

	kpatch_offset_t kpatch_offset;	/* content offset */
	kpatch_offset_t rel_offset;	/* relocations offset (vmlinux) */
	kpatch_offset_t total_size;	/* total size = header + relocations + content */
	kpatch_offset_t jmp_offset;	/* jump table offset for user-space patches */

	/* array of entry offsets in the patch content */
	union {
		kpatch_offset_t entries[KPATCH_MAX_NR_ENTRIES];
		struct {
			kpatch_offset_t kpatch_entry;
			kpatch_offset_t kpatch_unpatch;
			kpatch_offset_t kpatch_kallsyms_lookup_name;
			kpatch_offset_t kpatch_delta;
			struct {
				kpatch_offset_t offset;
				kpatch_offset_t size;
			} kpatch_dwarf;
		};
		struct {
			kpatch_offset_t elf_hdr;	/* saved offset to ELF hdr */
			kpatch_offset_t extbl_start;	/* exception table start for modules */
			kpatch_offset_t extbl_end;	/* exception table end for modules */
			kpatch_offset_t bugtbl_start;	/* bug table start for modules */
			kpatch_offset_t bugtbl_end;	/* bug table end for modules */
		};
		struct {
			kpatch_offset_t user_undo;	/* undo information for userspace */
			kpatch_offset_t user_info;	/* patch information */
		};
	};

	char srcversion[25]; /* srcversion of module or zeros */
	char pad2[231];

	/* relocations */
	/* content */
};

struct kpatch_reloc {
	kpatch_reloc_t offset;	/* offset in file */
	signed char type_low;		/* relocation type, low byte */
/* possible pcrel values according to area offset points to:
 * ==  0 - offset points to kpatch area,
 * ==  1 - offset points to vmlinux area,
 * == -1 - offset points to per_cpu variable */
#define KPATCH_PCREL_EXT_KPATCH (0)
#define KPATCH_PCREL_EXT_VMLINUX (1)
#define KPATCH_PCREL_EXT_PER_CPU (-1)
	signed char pcrel;		/* pcrel = 0 => code reloation +x bytes should adjust relocation value by +x, otherwise -x */
	signed char type_high;		/* relocation type, high byte */
	signed char pad[1];
	signed char pad2[4];
	union {
		kpatch_reloc_t delta;	/* not used for patching, only during make stage */
		kpatch_reloc_t value;	/* used for ARM64 */
	};
};

#ifndef UINT16_MAX
#define UINT16_MAX 0xffff
#endif

static inline int reloc_set_type(struct kpatch_reloc *reloc, uint32_t type)
{
	if (type >= UINT16_MAX) {
		return -ERANGE;
	}

	reloc->type_low = type & 0xFF;
	reloc->type_high = (type >> 8) & 0xFF;

	return 0;
}

static inline uint32_t reloc_get_type(const struct kpatch_reloc *reloc)
{
	return reloc->type_low | (reloc->type_high << 8);
}

#define KPATCH_INFO_PTR64(name) union { unsigned long name; uint64_t name ## 64; }
struct kpatch_info {
	KPATCH_INFO_PTR64(daddr);
	KPATCH_INFO_PTR64(saddr);
	uint32_t dlen;
	uint32_t slen;
	KPATCH_INFO_PTR64(symstr);
	KPATCH_INFO_PTR64(vaddr);
	uint32_t flags;
	char     pad[4];
};

struct kpatch_query_info {
	/* Patch state */
#define KPATCH_STATE_NONE	0	/* No patch applied */
#define KPATCH_STATE_APPLIED	1	/* Patch is applied */
	uint32_t state;

	char uname[KPATCH_UNAME_LEN];
	char description[512];

	uint64_t build_time;
	/* Add info about patch (name?/modules?, etc.) */
	char pad[1024];
};

static inline int is_end_info(const struct kpatch_info *info)
{
	return (info->daddr == 0) && (info->dlen == 0) &&
		(info->saddr == 0) && (info->slen == 0);
}

static inline int is_new_func(const struct kpatch_info *info)
{
	return (info->daddr == 0) && (info->dlen == 0);
}

static inline struct kpatch_info *kpatch_file_info(struct kpatch_file *kpatch)
{
	return (void *)kpatch + kpatch->kpatch_offset;
}

static inline struct kpatch_file *kpatch_file_next(struct kpatch_file *kpatch)
{
	return (void *)kpatch + kpatch->total_size;
}

#define kpatch_for_all(pos, head, iter) \
	for (pos = (head); iter; pos = kpatch_file_next(pos), iter--)


#ifdef __KERNEL__

static inline int kpatch_time_expired(uint64_t max_wait_period)
{
	return time_before64(get_jiffies_64(), max_wait_period) == 0;
}

/**
 * enum fimask_values - Fault Injection flags
 * @KPATCH_FI_SAFETY_CHECK: Fail all stack safety checks.
 * @KPATCH_FI_SAFETY_CHECK_USER: Fail non-kthread stack safety checks.
 * @KPATCH_FI_SAFETY_CHECK_RELOCK: Fail stack safety checks as if we have a
 *                                 conflict which requires relock and retry.
 * @KPATCH_FI_SWITCH_CPUS_ONLINE: Fail routine that switches offline CPUs back
 *                                into online.
 * @KPATCH_FI_DELAY_TASK_VERIFICATION: Delay verification of each task for 1s.
 *                                     This should be enough to trigger a
 *                                     hardlockup_detector if it is enabled.
 * @KPATCH_FI_TIMEOUT_EXECUTE_SAFE: Fail kpatch_execute_safe() timeout.
 * @KPATCH_FI_FAIL_PATCHING: Failure to apply the patch.
 *
 * Enumeration of all possible Fault Injection flags, each flag corresponds to
 * a fault that can be introduced through '/proc/kcare/opt/faultinject'
 * interface.
 */
enum fimask_values {
	KPATCH_FI_SAFETY_CHECK,
	KPATCH_FI_SAFETY_CHECK_USER,
	KPATCH_FI_SAFETY_CHECK_RELOCK,
	KPATCH_FI_SWITCH_CPUS_ONLINE,
	KPATCH_FI_DELAY_TASK_VERIFICATION,
	KPATCH_FI_TIMEOUT_EXECUTE_SAFE,
	KPATCH_FI_FAIL_PATCHING,
};

/**
 * enum fi_mod_value - Fault Injection modules flags
 * @KPATCH_FI_INITCALL: Fail regular initcalls.
 *
 * Enumeration of all possible Fault Injection flags, each flag corresponds to
 * a fault that can be introduced through '/proc/kcare/opt/faultinject_mod'
 * interface.
 */
enum fi_mod_value {
	KPATCH_FI_INITCALL = 0,
	KPATCH_FI_MOD_MAX
};

static inline int fimask_check(const atomic_t *mask, int flag)
{
	if (atomic_read(mask) & (1 << flag))
		return 1;
	return 0;
}


/**
 * struct fault_injection - A common structure for fault injection and module's
 * initcall/exitcall fault injection
 * @fimask:    Mask to enable/disable specific fault types
 * @call:      Module fault injection mode
 * @mod:       Module name to fault the call
 * @idx:       Module call index to fault
 * @cur_idx:   Internal index to track the executed calls number
 */
struct fault_injection {
	atomic_t fimask;
	enum fi_mod_value call;
	char mod[MOD_STR_LEN];
	uint8_t idx;
	uint8_t cur_idx;
};

/* Use fixed size struct to avoid future problems with data
 * expansion. 1Kb should be enough if not we could add
 * kpatch_kmod_data2..N structs. */
struct kpatch_kmod_data {
	int debug;
	int safety_method;
	struct fault_injection fi;
	int skip_cpus;
	uint64_t max_wait_period;
	uint32_t kpatch_retries;
	union {
		uintptr_t patchinfo;
		uint64_t  patchinfo_64;
	};
	union {
		size_t    patchinfo_size;
		uint64_t  patchinfo_size_64;
	};
	union {
		uintptr_t cvelist;
		uint64_t  cvelist_64;
	};
	union {
		size_t    cvelist_size;
		uint64_t  cvelist_size_64;
	};
	unsigned int kcore_output;
	unsigned int kmsg_output;
	struct {
		void **info;
		size_t nr_info;
	} gcov;
} __aligned(PAGE_SIZE);

struct mutex;

struct kpatch_context {
	struct mutex *lock;
	struct kpatch_file *patch;
	void *undo_data;
	struct kpatch_kmod_data kmod_data;
};

#endif /* __KERNEL__ */

#endif /* __KCARE_FILE_H__ */
