#!/usr/bin/env python3
"""Inject an OrangeFox cpio as the type-2 recovery fragment of a stock
vendor_boot v4 image, preserving every other byte of the container.

Usage: repack_2frag.py <stock.img> <recovery.lz4> <out.img>
"""
import struct, subprocess, sys, hashlib
from pathlib import Path

HEADER_SIZE_V4, ENTRY_SIZE_V4, FOOTER = 2128, 108, 64
align = lambda v, a: (v + a - 1) // a * a


def parse(img):
    if img[:8] != b"VNDRBOOT":
        raise SystemExit("not a vendor_boot image")
    ver, page = struct.unpack_from("<II", img, 8)
    rd_size = struct.unpack_from("<I", img, 24)[0]
    hs, dtb_size = struct.unpack_from("<II", img, 2096)
    t_size, n, e_size, bc_size = struct.unpack_from("<IIII", img, 2112)
    if ver != 4 or hs != HEADER_SIZE_V4:
        raise SystemExit(f"unsupported header v{ver} size {hs}")
    if e_size < ENTRY_SIZE_V4 or t_size != n * e_size:
        raise SystemExit("invalid ramdisk table")
    rd_off = align(hs, page)
    dtb_off = align(rd_off + rd_size, page)
    t_off = align(dtb_off + dtb_size, page)
    bc_off = align(t_off + t_size, page)
    entries, expect = [], 0
    for i in range(n):
        eo = t_off + i * e_size
        size, off, rtype = struct.unpack_from("<III", img, eo)
        if off != expect or off + size > rd_size:
            raise SystemExit(f"bad fragment range at entry {i}")
        entries.append({
            "i": i, "size": size, "off": off, "type": rtype,
            "name": img[eo + 12:eo + 44].split(b"\0")[0].decode(),
            "payload": img[rd_off + off:rd_off + off + size],
        })
        expect += size
    if expect != rd_size:
        raise SystemExit("fragment total != vendor_ramdisk_size")
    return dict(page=page, hs=hs, rd_off=rd_off, dtb_off=dtb_off,
                dtb_end=dtb_off + dtb_size, t_off=t_off, t_end=t_off + t_size,
                bc_off=bc_off, bc_end=bc_off + bc_size, e_size=e_size,
                entries=entries)


def footer_original_size(img):
    m, _, _, orig, _, _ = struct.unpack_from(">4sIIQQQ28x", img, len(img) - FOOTER)
    if m != b"AVBf":
        raise SystemExit("no AVB footer on stock image")
    return orig


def main():
    stock_p, rec_p, out_p = map(Path, sys.argv[1:4])
    stock = stock_p.read_bytes()
    c = parse(stock)
    new = rec_p.read_bytes()

    targets = [e for e in c["entries"] if e["type"] == 2 and e["name"] == "recovery"]
    if len(targets) != 1:
        raise SystemExit(f"expected 1 type-2 'recovery' fragment, found {len(targets)}")
    tgt = targets[0]["i"]

    payloads, table_patch, nxt = [], [], 0
    for e in c["entries"]:
        p = new if e["i"] == tgt else e["payload"]
        payloads.append(p)
        table_patch.append((e["i"], len(p), nxt))
        nxt += len(p)
        tag = "REPLACED" if e["i"] == tgt else "preserved"
        print(f"  frag[{e['i']}] type={e['type']} name={e['name']!r:12} "
              f"{e['size']:>9} -> {len(p):>9}  {tag}")

    page = c["page"]
    hdr = bytearray(stock[:c["hs"]])
    struct.pack_into("<I", hdr, 24, nxt)           # vendor_ramdisk_size
    table = bytearray(stock[c["t_off"]:c["t_end"]])
    for i, size, off in table_patch:
        struct.pack_into("<II", table, i * c["e_size"], size, off)

    img = bytearray(hdr)
    img += b"\0" * (align(len(img), page) - len(img))
    for p in payloads:
        img += p
    img += b"\0" * (align(len(img), page) - len(img))
    img += stock[c["dtb_off"]:c["dtb_end"]]        # dtb verbatim
    img += b"\0" * (align(len(img), page) - len(img))
    img += table
    img += b"\0" * (align(len(img), page) - len(img))
    img += stock[c["bc_off"]:c["bc_end"]]          # bootconfig verbatim
    img += b"\0" * (align(len(img), page) - len(img))

    budget = footer_original_size(stock)
    if len(img) > len(stock) - FOOTER:
        raise SystemExit(f"FATAL: {len(img)} bytes exceeds partition "
                         f"{len(stock)} (stock base was {budget})")
    out_p.write_bytes(bytes(img))

    # header: everything except vendor_ramdisk_size@24 must be untouched
    o = parse(bytes(img))
    checks = {
        "header_except_ramdisk_size": stock[:24] == img[:24] and stock[28:c["hs"]] == img[28:c["hs"]],
        "dtb_preserved": stock[c["dtb_off"]:c["dtb_end"]] == img[o["dtb_off"]:o["dtb_end"]],
        "bootconfig_preserved": stock[c["bc_off"]:c["bc_end"]] == img[o["bc_off"]:o["bc_end"]],
        "entry_count_is_2": len(o["entries"]) == 2,
        "types_preserved": [e["type"] for e in o["entries"]] == [e["type"] for e in c["entries"]],
        "names_preserved": [e["name"] for e in o["entries"]] == [e["name"] for e in c["entries"]],
        "platform_frag_untouched": o["entries"][0]["payload"] == c["entries"][0]["payload"],
    }
    for k, v in checks.items():
        print(f"  {'OK  ' if v else 'FAIL'} {k}")
    if not all(checks.values()):
        out_p.unlink()
        raise SystemExit("container validation failed")
    print(f"  base image: {len(img)} bytes, sha256 {hashlib.sha256(img).hexdigest()[:16]}")


if __name__ == "__main__":
    main()
