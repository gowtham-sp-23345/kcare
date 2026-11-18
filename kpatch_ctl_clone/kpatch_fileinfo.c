/*
 * kpatch_fileinfo - behavioural re-implementation of
 *     kpatch_ctl [-v] file-info <patch>
 *
 * Written from observation of the shipped /usr/libexec/kcare/kpatch_ctl
 * (strings, disassembly) and of kpatch.bin files. It is NOT the original
 * source. It only reads the patch file and never talks to /dev/kcare.
 *
 * kpatch.bin layout (little endian):
 *
 *   [ module block 0 ][ module block 1 ] ... [ module_signature + marker ]?
 *
 * Every module block starts with a header (min. 0x2b0 bytes):
 *
 *   0x000  char     magic[8]            "KPATCH1"
 *   0x010  char     module_name[64]     "vmlinux", "8021q", ...
 *   0x050  char     kernel_version[256] /proc/version of the target kernel
 *   0x150  u64      build_time          time_t
 *   0x158  u32      (checksum, unused here)
 *   0x15c  u32      nr_relocs           16-byte records
 *   0x160  u32      end_off             end of the extra relocs, from block start
 *   0x164  u32      hdr_len             header length (0x2b0)
 *   0x168  u32      block_size          size of this whole module block
 *   0x170  u32      entry[16]
 *
 * Extra relocations are the 16-byte records between
 *   block + hdr_len + nr_relocs * 16   and   block + end_off.
 *
 * If the file ends with "~Module signature appended~\n" it is preceded by a
 * 12 byte struct module_signature whose big-endian u32 at offset 8 is the
 * length of the signature that sits in front of it. All of it is stripped
 * before parsing.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OFF_MAGIC     0x000
#define OFF_NAME      0x010
#define OFF_KVER      0x050
#define OFF_TIME      0x150
#define OFF_NRELOCS   0x15c
#define OFF_END       0x160
#define OFF_HDRLEN    0x164
#define OFF_BLKSIZE   0x168
#define OFF_ENTRIES   0x170
#define NR_ENTRIES    16
#define MIN_HDR_LEN   0x2b0

#define SIG_MARKER      "~Module signature appended~\n"
#define SIG_MARKER_LEN  (sizeof(SIG_MARKER) - 1)	/* 28 */
#define SIG_FOOTER_LEN  0x28				/* 12 + 28 */

static uint32_t u32(const unsigned char *p, size_t off)
{
	uint32_t v;

	memcpy(&v, p + off, sizeof(v));
	return v;
}

static uint64_t u64(const unsigned char *p, size_t off)
{
	uint64_t v;

	memcpy(&v, p + off, sizeof(v));
	return v;
}

/* Strip an appended module signature. Returns 0 or -1 on a bad sig_len. */
static int strip_signature(const unsigned char *data, size_t *size)
{
	const unsigned char *footer;
	uint32_t sig_len;

	if (*size <= SIG_MARKER_LEN ||
	    memcmp(data + *size - SIG_MARKER_LEN, SIG_MARKER, SIG_MARKER_LEN))
		return 0;

	footer = data + *size - SIG_FOOTER_LEN;
	sig_len = __builtin_bswap32(u32(footer, 8));
	if ((uint64_t)sig_len + SIG_FOOTER_LEN >= *size) {
		printf("invalid sig_len value: %u/%zu\n", sig_len, *size);
		return -1;
	}
	*size -= SIG_FOOTER_LEN + sig_len;
	return 0;
}

static int check_header(const unsigned char *blk, size_t remaining)
{
	if (remaining < MIN_HDR_LEN) {
		puts("Invalid patch header length");
		return -1;
	}
	if (remaining < u32(blk, OFF_BLKSIZE)) {
		puts("Invalid patch size");
		return -1;
	}
	if (u32(blk, OFF_END) < MIN_HDR_LEN ||
	    u32(blk, OFF_BLKSIZE) < u32(blk, OFF_END)) {
		puts("Invalid patch offset");
		return -1;
	}
	if (strnlen((const char *)blk + OFF_MAGIC, 8) > 7) {
		puts("Invalid patch magic number length");
		return -1;
	}
	if (strnlen((const char *)blk + OFF_NAME, 0x40) > 0x3f) {
		puts("Invalid patch module name length");
		return -1;
	}
	if (strnlen((const char *)blk + OFF_KVER, 0x100) > 0xff) {
		puts("Invalid patch kernel version length");
		return -1;
	}
	return 0;
}

static int file_info(const unsigned char *data, size_t size, int verbose)
{
	const unsigned char *blk = data;
	size_t remaining = size;
	time_t t;
	int i;

	if (strip_signature(data, &remaining))
		return -1;
	size = remaining;

	if (check_header(blk, remaining)) {
		errno = EINVAL;
		return -1;
	}

	t = (time_t)u64(blk, OFF_TIME);
	printf("kpatch-magic: %s\n", (const char *)blk + OFF_MAGIC);
	printf("kpatch-kernel-version: %s\n", (const char *)blk + OFF_KVER);
	printf("kpatch-build-time: %s", ctime(&t));
	printf("kpatch-modules:");

	while (remaining) {
		if (check_header(blk, remaining)) {
			errno = EINVAL;
			return -1;
		}
		printf(" %s", (const char *)blk + OFF_NAME);
		remaining -= u32(blk, OFF_BLKSIZE);
		blk += u32(blk, OFF_BLKSIZE);
	}
	putchar('\n');

	if (!verbose)
		return 0;

	blk = data;
	for (i = 0; i < NR_ENTRIES; i++)
		printf("kpatch-entry: %02d\t%016" PRIx32 "\n", i,
		       u32(blk, OFF_ENTRIES + i * 4));

	printf("kpatch-relocs: %d\n", (int)u32(blk, OFF_NRELOCS));
	{
		const unsigned char *start = blk + u32(blk, OFF_HDRLEN) +
					     (size_t)u32(blk, OFF_NRELOCS) * 16;
		const unsigned char *end = blk + u32(blk, OFF_END);

		printf("kpatch-relocs-extra: %ld\n", (long)((end - start) >> 4));
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *path;
	unsigned char *data;
	struct stat st;
	int verbose = 0, fd, rc;

	if (argc == 3 && !strcmp(argv[1], "-v")) {
		verbose = 1;
		argv++;
		argc--;
	}
	if (argc != 2) {
		fprintf(stderr, "usage: %s [-v] <kpatch.bin>\n", argv[0]);
		return 2;
	}
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		printf("Failed to query file info for '%s': %s\n", path, strerror(errno));
		return 1;
	}
	data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		printf("Failed to query file info for '%s': %s\n", path, strerror(errno));
		return 1;
	}

	rc = file_info(data, st.st_size, verbose);
	if (rc)
		printf("Failed to query file info for '%s': %s\n", path, strerror(errno));

	munmap(data, st.st_size);
	close(fd);
	return rc ? 1 : 0;
}
