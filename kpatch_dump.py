#!/usr/bin/env python3
"""List functions patched by a kpatch.bin (vmlinux block only).

usage: kpatch_dump.py kpatch.bin [name-substring]
"""
import struct
import sys
import time

REC = struct.Struct('<QQIIQQI4x')  # struct kpatch_info, 48 bytes


def cstr(buf, off):
    end = buf.index(b'\0', off)
    return buf[off:end].decode('ascii', 'replace')


SIG_MARKER = b'~Module signature appended~\n'
SIG_FOOTER_LEN = 12 + len(SIG_MARKER)


def strip_signature(buf):
    """Return the length of the patch data without an appended signature."""
    if not buf.endswith(SIG_MARKER):
        return len(buf)
    footer = len(buf) - SIG_FOOTER_LEN
    sig_len = struct.unpack_from('>I', buf, footer + 8)[0]
    return len(buf) - SIG_FOOTER_LEN - sig_len


def dump_elf_records(buf, elf, name, pat):
    """Module blocks embed a relocatable ELF; its .kpatch.info holds the records.

    daddr/saddr/symstr are ELF relocations, so they are shown as symbol+addend.
    """
    shoff, = struct.unpack_from('<Q', buf, elf + 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', buf, elf + 0x3a)
    secs = []
    for n in range(shnum):
        nm, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            '<IIQQQQIIQQ', buf, elf + shoff + n * shentsize)
        secs.append((nm, typ, off, size, link, info))
    shstr = elf + secs[shstrndx][2]
    names = [cstr(buf, shstr + s[0]) for s in secs]

    def sec(name_):
        return names.index(name_) if name_ in names else None

    ii, ri, si = sec('.kpatch.info'), sec('.rela.kpatch.info'), sec('.kpatch.strtab')
    if ii is None or ri is None or si is None:
        print('   (no .kpatch.info in this block)')
        print()
        return

    symtab = secs[ri][4]
    sym_off, sym_size = secs[symtab][2], secs[symtab][3]
    symstr_off = elf + secs[secs[symtab][4]][2]

    def symname(idx):
        nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', buf, elf + sym_off + idx * 24)
        return cstr(buf, symstr_off + nm) if nm else names[shndx]

    relocs = {}
    r_off, r_size = elf + secs[ri][2], secs[ri][3]
    for k in range(r_size // 24):
        o, info, addend = struct.unpack_from('<QQq', buf, r_off + k * 24)
        relocs[o] = (symname(info >> 32), addend)

    info_off, info_size = elf + secs[ii][2], secs[ii][3]
    strtab = elf + secs[si][2]
    count = 0
    for r in range(info_size // REC.size):
        rec = r * REC.size
        if all(b == 0 for b in buf[info_off + rec:info_off + rec + REC.size]) and not relocs.get(rec):
            break
        _, _, dlen, slen, _, _, flags = REC.unpack_from(buf, info_off + rec)
        d = relocs.get(rec)
        s = relocs.get(rec + 8)
        y = relocs.get(rec + 0x18)
        sym = cstr(buf, strtab + y[1]) if y else ''
        dstr = '%s+0x%x' % d if d else '0'
        sstr = '%s+0x%x' % s if s else '0'
        if pat is None or pat in sym:
            print('%-5d %-10s %-22s %-22s %-6d %-6d %s' % (r, name, dstr, sstr, dlen, slen, sym))
        count += 1
    print('   records: %d' % count)
    print()


def dump_block(buf, base, pat):
    """Dump one module block (struct kpatch_file) starting at buf[base]."""
    name = cstr(buf, base + 0x10)
    build_time, csum, nr_reloc, koff, roff, total, jmp = struct.unpack_from('<QIIIIII', buf, base + 0x150)
    entries = struct.unpack_from('<16I', buf, base + 0x170)

    print('== module %s: block_off=0x%x total_size=%d kpatch_offset=0x%x nr_reloc=%d built=%s' % (
        name, base, total, koff, nr_reloc, time.ctime(build_time)))
    if buf[base + koff:base + koff + 4] == b'\x7fELF':
        dump_elf_records(buf, base + koff, name, pat)
        return total

    print('   entry file offset 0x%x, unpatch 0x%x, dwarf size %d' % (
        base + koff + entries[0], base + koff + entries[1], entries[5]))

    pos = base + koff
    i = patched = new = 0
    while True:
        daddr, saddr, dlen, slen, symstr, vaddr, flags = REC.unpack_from(buf, pos)
        if daddr == 0 and dlen == 0 and saddr == 0 and slen == 0:
            break
        sym = cstr(buf, base + koff + symstr) if symstr else ''
        is_new = daddr == 0 and dlen == 0
        if is_new:
            new += 1
        else:
            patched += 1
        if pat is None or pat in sym:
            print('%-5d %-10s 0x%016x 0x%-8x %-6d %-6d %s%s' % (
                i, name, daddr, saddr, dlen, slen, sym, '  [new]' if is_new else ''))
        i += 1
        pos += REC.size
    print('   records: %d (replaced: %d, new: %d)' % (i, patched, new))
    print()
    return total


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 else None

    with open(path, 'rb') as f:
        buf = f.read()
    end = strip_signature(buf)

    print('%-5s %-10s %-18s %-10s %-6s %-6s %s' % ('#', 'module', 'daddr(old)', 'saddr', 'dlen', 'slen', 'symbol'))
    base = 0
    while base < end:
        if buf[base:base + 6] != b'KPATCH':
            sys.exit('bad magic at offset 0x%x' % base)
        base += dump_block(buf, base, pat)


if __name__ == '__main__':
    main()
