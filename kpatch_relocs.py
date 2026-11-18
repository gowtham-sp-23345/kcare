#!/usr/bin/env python3
"""Show relocations (struct kpatch_reloc) of the vmlinux block of a kpatch.bin.

usage: kpatch_relocs.py kpatch.bin [-m module] [-v] [-s kallsyms.txt] [--slide 0x...] [-g substr]

  -m MODULE    block to dump: vmlinux (default) or a module name, e.g. act_pedit
               (functions of modules such as tcf_pedit_act are NOT in the vmlinux block;
               find the module with kpatch_dump.py kpatch.bin <function>)
  -v           list every relocation (default: only the summary)
  -s FILE      "addr type name" symbol file (System.map or /proc/kallsyms dump)
               used to turn the relocation target into a symbol name
  --slide HEX  KASLR slide of the kallsyms file (default: derived from _stext)
  -g SUBSTR    only list relocations whose location or target contains SUBSTR

The blob does not store relocation symbol names (struct kpatch_reloc has only
offset/type/pcrel). The name is recovered from:
  - location: which kpatch_info field / replacement function the reloc is in
  - target  : the value stored at that location (link-time address or patch offset)
"""
import bisect
import struct
import sys

RELOC = struct.Struct('<IbbbxxxxxI')  # offset, type_low, pcrel, type_high, pad(5), delta = 16 bytes
REC = struct.Struct('<QQIIQQI4x')  # struct kpatch_info, 48 bytes
PCREL = {0: 'KPATCH', 1: 'VMLINUX', -1: 'PER_CPU'}
X86_64 = {
    0: 'R_X86_64_NONE', 1: 'R_X86_64_64', 2: 'R_X86_64_PC32', 3: 'R_X86_64_GOT32',
    4: 'R_X86_64_PLT32', 10: 'R_X86_64_32', 11: 'R_X86_64_32S', 24: 'R_X86_64_PC64',
}
LINK_STEXT = 0xffffffff81000000
FIELDS = {0: 'daddr', 8: 'saddr', 0x18: 'symstr', 0x20: 'vaddr'}


def cstr(buf, off):
    return buf[off:buf.index(b'\0', off)].decode('ascii', 'replace')


SIG_MARKER = b'~Module signature appended~\n'
SIG_FOOTER_LEN = 12 + len(SIG_MARKER)


def patch_end(buf):
    if not buf.endswith(SIG_MARKER):
        return len(buf)
    footer = len(buf) - SIG_FOOTER_LEN
    return footer - struct.unpack_from('>I', buf, footer + 8)[0]


def find_block(buf, module):
    """Walk the concatenated blocks and return (offset, names) of the requested module."""
    base, end, names = 0, patch_end(buf), []
    while base < end:
        if buf[base:base + 6] != b'KPATCH':
            sys.exit('bad magic at offset 0x%x' % base)
        name = buf[base + 0x10:base + 0x50].split(b'\0')[0].decode()
        if name == module:
            return base, names
        names.append(name)
        base += struct.unpack_from('<I', buf, base + 0x168)[0]
    return None, names


def dump_elf_relocs(buf, elf, verbose, grep):
    """Module blocks embed an ELF object: relocations are ordinary .rela.* entries with symbol names."""
    shoff, = struct.unpack_from('<Q', buf, elf + 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', buf, elf + 0x3a)
    secs = []
    for n in range(shnum):
        nm, typ, _, _, off, size, link, info, _, _ = struct.unpack_from('<IIQQQQIIQQ', buf, elf + shoff + n * shentsize)
        secs.append((nm, typ, off, size, link, info))
    shstr = elf + secs[shstrndx][2]
    names = [cstr(buf, shstr + s[0]) for s in secs]

    # Replacement function names live in .kpatch.strtab, referenced by the symstr
    # field (info record + 0x18) of .kpatch.info; the function start is its saddr
    # (info record + 0x8, a .kpatch.text+off relocation).
    strtab_sec = names.index('.kpatch.strtab') if '.kpatch.strtab' in names else None
    strtab_base = elf + secs[strtab_sec][2] if strtab_sec is not None else None
    funcs = {}   # text offset -> function name
    rows = []
    for n, (_, typ, off, size, link, info) in enumerate(secs):
        if typ != 4:  # SHT_RELA
            continue
        sym_off, strtab = elf + secs[link][2], elf + secs[secs[link][4]][2]
        pending = {}
        for k in range(size // 24):
            r_off, r_info, addend = struct.unpack_from('<QQq', buf, elf + off + k * 24)
            rtype, sidx = r_info & 0xffffffff, r_info >> 32
            nm, sinfo, _, shndx, _, _ = struct.unpack_from('<IBBHQQ', buf, sym_off + sidx * 24)
            sym = cstr(buf, strtab + nm) if nm else names[shndx]
            if names[n] == '.rela.kpatch.info' and strtab_base is not None:
                rec, field = divmod(r_off, 48)
                if field == 0x18 and sym == '.kpatch.strtab':
                    sym = '%s -> "%s"' % (sym, cstr(buf, strtab_base + addend))
                    pending.setdefault(rec, {})['name'] = cstr(buf, strtab_base + addend)
                elif field == 0x8:
                    pending.setdefault(rec, {})['start'] = addend
            rows.append((n, r_off, rtype, sym, addend))
        for rec in pending.values():
            if 'name' in rec and 'start' in rec:
                funcs[rec['start']] = rec['name']

    def func_at(off):
        starts = [s for s in funcs if s <= off]
        return funcs[max(starts)] if starts else ''

    print('replacement functions (.kpatch.strtab):')
    for start in sorted(funcs):
        print('  .kpatch.text+0x%-6x %s' % (start, funcs[start]))
    print()

    stats = {}
    if verbose:
        print('%-12s %-10s %-15s %-40s %-8s %s' % ('section', 'offset', 'type', 'symbol', 'addend', 'function'))
    for n, r_off, rtype, sym, addend in rows:
        tname = X86_64.get(rtype, 'type_%d' % rtype)
        stats[(names[n], tname)] = stats.get((names[n], tname), 0) + 1
        fn = func_at(r_off) if names[n] == '.rela.kpatch.text' else ''
        if verbose and (not grep or grep in sym or grep in names[n] or grep in fn):
            print('%-12s 0x%08x %-15s %-40s %-8s %s' % (names[n][6:], r_off, tname, sym, '%+d' % addend, fn))

    print('\n%-26s %-16s %s' % ('section', 'type', 'count'))
    for (s, t), c in sorted(stats.items()):
        print('%-26s %-16s %d' % (s, t, c))


class Symbols(object):
    def __init__(self, path, slide):
        kern, percpu = [], []
        stext = None
        with open(path) as f:
            for line in f:
                p = line.split()
                if len(p) < 3:
                    continue
                addr = int(p[0], 16)
                if p[2] == '_stext':
                    stext = addr
                (kern if addr >= 0xffffffff80000000 else percpu).append((addr, p[2]))
        if slide is None:
            slide = (stext - LINK_STEXT) if stext else 0
        self.slide = slide
        self.kern = sorted((a - slide, n) for a, n in kern)
        self.kaddrs = [a for a, _ in self.kern]
        self.percpu = sorted((a, n) for a, n in percpu if a < 0x10000000)
        self.paddrs = [a for a, _ in self.percpu]

    @staticmethod
    def _near(addrs, syms, addr):
        i = bisect.bisect_right(addrs, addr) - 1
        if i < 0:
            return '?'
        a, n = syms[i]
        return n if a == addr else '%s+0x%x' % (n, addr - a)

    def kernel(self, addr):
        return self._near(self.kaddrs, self.kern, addr)

    def per_cpu(self, addr):
        return self._near(self.paddrs, self.percpu, addr)


def main():
    argv = sys.argv[1:]
    if not argv:
        sys.exit(__doc__)
    opts = {'-s': None, '--slide': None, '-g': None, '-m': 'vmlinux'}
    verbose = False
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '-v':
            verbose = True
        elif a in opts:
            i += 1
            opts[a] = argv[i]
        else:
            pos.append(a)
        i += 1
    buf = open(pos[0], 'rb').read()
    base, others = find_block(buf, opts['-m'])
    if base is None:
        sys.exit('module %r not found (%d blocks, e.g. %s)' % (opts['-m'], len(others), ', '.join(others[:8])))
    slide = int(opts['--slide'], 16) if opts['--slide'] else None
    syms = Symbols(opts['-s'], slide) if opts['-s'] else None
    grep = opts['-g']

    nr_reloc, koff, roff, total = struct.unpack_from('<IIII', buf, base + 0x15c)
    name = buf[base + 0x10:base + 0x50].split(b'\0')[0].decode()
    content = base + koff
    print('block %s: nr_reloc=%d rel_offset=0x%x kpatch_offset=0x%x total=%d' % (name, nr_reloc, roff, koff, total))
    if buf[content:content + 4] == b'\x7fELF':
        dump_elf_relocs(buf, content, verbose, grep)
        return
    if syms:
        print('symbols: kernel slide 0x%x' % syms.slide)

    # kpatch_info table at the start of the content
    recs = []
    p = content
    while True:
        daddr, saddr, dlen, slen, symstr, vaddr, flags = REC.unpack_from(buf, p)
        if daddr == 0 and dlen == 0 and saddr == 0 and slen == 0:
            break
        recs.append((saddr, slen, cstr(buf, content + symstr) if symstr else ''))
        p += REC.size
    table_end = (len(recs) + 1) * REC.size
    by_saddr = sorted((s, l, n) for s, l, n in recs if s)
    saddrs = [s for s, _, _ in by_saddr]

    def patch_name(off):
        j = bisect.bisect_right(saddrs, off) - 1
        if j >= 0:
            s, l, n = by_saddr[j]
            if off < s + l:
                return '%s+0x%x' % (n, off - s)
        return 'patch+0x%x' % off

    simple_end = roff + nr_reloc * RELOC.size
    n_extra = (koff - simple_end) // RELOC.size
    print('simple relocs: %d (no ELF type, only pcrel flag)' % nr_reloc)
    print('extra relocs : %d' % n_extra)

    stats = {}
    if verbose:
        print('%6s  %-10s %-15s %-8s %-34s %s' % ('#', 'off', 'type', 'area', 'location', 'target'))
    for i in range(n_extra):
        off, tl, pcrel, th, _ = RELOC.unpack_from(buf, base + simple_end + i * RELOC.size)
        rtype = (tl & 0xff) | ((th & 0xff) << 8)
        tname = X86_64.get(rtype, 'type_%d' % rtype)
        area = PCREL.get(pcrel, str(pcrel))
        stats[(tname, area)] = stats.get((tname, area), 0) + 1
        if not verbose:
            continue

        # location
        if off < table_end:
            idx, fld = divmod(off, REC.size)
            sym = recs[idx][2] if idx < len(recs) else ''
            loc = 'info[%d].%s (%s)' % (idx, FIELDS.get(fld, '+0x%x' % fld), sym)
        else:
            loc = patch_name(off)

        # target: value stored at the location (addend A is -4 for pc-relative, 0 otherwise)
        if rtype in (1, 24):
            v = int.from_bytes(buf[content + off:content + off + 8], 'little')
        else:
            v = int.from_bytes(buf[content + off:content + off + 4], 'little', signed=(rtype != 10)) & 0xffffffffffffffff
        if rtype in (2, 4, 24):
            v = (v + 4) & 0xffffffffffffffff
        if area == 'VMLINUX':
            tgt = '0x%x' % v
            if syms:
                tgt += ' ' + syms.kernel(v)
        elif area == 'PER_CPU':
            tgt = '0x%x' % v
            if syms:
                tgt += ' ' + syms.per_cpu(v)
        else:
            tgt = patch_name(v)
        if grep and grep not in loc and grep not in tgt:
            continue
        print('%6d  0x%08x %-15s %-8s %-34s %s' % (i, off, tname, area, loc, tgt))

    print('\n%-18s %-8s %s' % ('type', 'area', 'count'))
    for (t, a), c in sorted(stats.items()):
        print('%-18s %-8s %d' % (t, a, c))


if __name__ == '__main__':
    main()
