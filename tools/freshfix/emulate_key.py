#!/usr/bin/env python3
"""
Recover the 4-byte PBKDF2 password from the freshfix loader by *emulating* the
arm64 slice. The sample is never executed natively: Unicorn interprets the
instructions, every libSystem call is stubbed in Python, and the emulator has no
access to files, network or syscalls.

Target: the value written to [sp+0x9c] at 0x1000017e8, and the derived 4-byte
key stored at [sp+0xfc] at 0x10000322c.

    uv run python emulate_key.py slice_arm64.bin

Extract the slice first, e.g. with `lipo -thin arm64 -output slice_arm64.bin sample.bin`.
Reference loader: SHA256 29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40
"""

import argparse
import struct
import sys
import pathlib
from unicorn import *
from unicorn.arm64_const import *

STACK_BASE, STACK_SIZE = 0x200000000, 0x400000
HEAP_BASE, HEAP_SIZE = 0x300000000, 0x400000
FAKE_BASE, FAKE_SIZE = 0x400000000, 0x1000

STUBS_LO, STUBS_HI = 0x1000057D4, 0x10000587C
STUB_NAMES = {
    0x1000057D4: "_dyld_get_image_header", 0x1000057E0: "bzero",
    0x1000057EC: "dlsym", 0x1000057F8: "free",
    0x100005804: "getenv", 0x100005810: "getsectiondata",
    0x10000581C: "malloc", 0x100005828: "memcpy",
    0x100005834: "mlock", 0x100005840: "mmap",
    0x10000584C: "munlock", 0x100005858: "munmap",
    0x100005864: "pthread_main_np", 0x100005870: "strstr",
}

WATCH_W9_AT = 0x1000017E8   # str w9, [sp, #0x9c]
WATCH_KEY_AT = 0x10000322C  # str w8, [sp, #0xfc]


def segments(d):
    ncmds = struct.unpack("<I", d[16:20])[0]
    out, off = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        if cmd == 0x19:
            name = d[off + 8:off + 24].rstrip(b"\0").decode()
            vm, vmsz, fo, fsz = struct.unpack("<QQQQ", d[off + 24:off + 56])
            out.append((name, vm, vmsz, fo, fsz))
        off += size
    return out


class Emu:
    def __init__(self, data, getenv_map=None, trace=False):
        self.d = data
        self.trace = trace
        self.getenv_map = getenv_map or {}
        self.heap = HEAP_BASE
        self.fake_next = FAKE_BASE
        self.fake_names = {}
        self.resolved = []
        self.log = []
        self.hits = {}
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._map()
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _map(self):
        uc = self.uc
        for name, vm, vmsz, fo, fsz in segments(self.d):
            if name == "__PAGEZERO":
                continue
            size = (max(vmsz, fsz) + 0xFFF) & ~0xFFF
            uc.mem_map(vm, size)
            if fsz:
                uc.mem_write(vm, self.d[fo:fo + fsz])
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        uc.mem_map(FAKE_BASE, FAKE_SIZE)
        # __DATA_CONST,__got holds ___chkstk_darwin and dyld_stub_binder, both
        # unbound in the file. Point them at fake pages so the blr is catchable.
        for i, nm in enumerate(("___chkstk_darwin", "dyld_stub_binder")):
            uc.mem_write(0x100008000 + i * 8,
                         struct.pack("<Q", self._fake_for(nm)))

    def alloc(self, n):
        p = self.heap
        self.heap = (self.heap + n + 15) & ~15
        return p

    def cstr(self, addr):
        if not addr:
            return None
        out = b""
        while len(out) < 512:
            c = self.uc.mem_read(addr + len(out), 1)
            if c == b"\0":
                break
            out += c
        return out

    def _fake_for(self, name):
        for a, n in self.fake_names.items():
            if n == name:
                return a
        a = self.fake_next
        self.fake_next += 8
        self.fake_names[a] = name
        return a

    # ---- stubbed libSystem ------------------------------------------------
    def _call(self, name):
        uc = self.uc
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
        ret = 0
        if name == "_dyld_get_image_header":
            ret = 0x100000000
        elif name == "getsectiondata":
            seg, sec = self.cstr(a[1]), self.cstr(a[2])
            if seg == b"__TEXT" and sec == b"__text":
                ret = 0x100000680
                uc.mem_write(a[3], struct.pack("<Q", 0x5154))
            elif seg == b"__DATA_CONST" and sec == b"__const":
                ret = 0x100008010
                uc.mem_write(a[3], struct.pack("<Q", 0x11000))
            else:
                ret = 0
            self.log.append(f"getsectiondata({seg},{sec}) -> {ret:#x}")
        elif name == "malloc":
            ret = self.alloc(a[0])
        elif name in ("free", "mlock", "munlock", "munmap"):
            ret = 0
        elif name == "memcpy":
            uc.mem_write(a[0], bytes(uc.mem_read(a[1], a[2])))
            ret = a[0]
        elif name == "bzero":
            uc.mem_write(a[0], b"\0" * a[1])
        elif name == "strstr":
            h, n = self.cstr(a[0]) or b"", self.cstr(a[1]) or b""
            i = h.find(n)
            ret = (a[0] + i) if i >= 0 else 0
            self.log.append(f"strstr({h!r},{n!r}) -> {ret:#x}")
        elif name == "getenv":
            k = self.cstr(a[0])
            v = self.getenv_map.get(k.decode(errors="replace") if k else "")
            if v is None:
                ret = 0
            else:
                p = self.alloc(len(v) + 1)
                uc.mem_write(p, v.encode() + b"\0")
                ret = p
            self.log.append(f"getenv({k!r}) -> {ret:#x}")
        elif name == "mmap":
            ret = self.alloc(a[1])
            uc.mem_write(ret, b"\0" * a[1])
            self.log.append(f"mmap(len={a[1]:#x}) -> {ret:#x}")
        elif name == "pthread_main_np":
            ret = 1
        elif name == "dlsym":
            sym = self.cstr(a[1]) or b"<null>"
            ret = self._fake_for(sym.decode(errors="replace"))
            self.resolved.append(sym.decode(errors="replace"))
        else:
            self.log.append(f"UNHANDLED stub {name}")
        uc.reg_write(UC_ARM64_REG_X0, ret)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    # Return values for APIs the loader resolves dynamically. These decide which
    # branch the anti-analysis logic takes, so they are the knobs of the
    # experiment: FAKE_RET is the "clean host" answer set.
    # Return values for APIs the loader resolves dynamically. These decide which
    # branch the anti-analysis logic takes, so they are the knobs of the
    # experiment: this is the "clean host, everything succeeds" answer set.
    # "H" = allocate a distinct non-NULL handle; ints are returned verbatim.
    # OSStatus-returning calls get 0 (noErr); pointer-returning calls get "H".
    FAKE_RET = {
        "dlopen": "H", "objc_getClass": "H", "sel_registerName": "H",
        "objc_msgSend": "H", "OpenDefaultComponent": "H",
        "IOServiceMatching": "H", "IOServiceGetMatchingService": "H",
        "IORegistryEntryCreateCFProperty": "H",
        "_dyld_image_count": 200, "pthread_main_np": 1,
        "AECreateDesc": 0, "AEDisposeDesc": 0, "OSALoad": 0, "OSAExecute": 0,
        "OSADispose": 0, "CloseComponent": 0, "TransformProcessType": 0,
        "sysctlbyname": 0, "mach_timebase_info": 0, "IOObjectRelease": 0,
        "CFRelease": 0,
    }

    def _fake_api(self, pc):
        """A dlsym-resolved API was called. Return a benign 'clean host' value."""
        uc = self.uc
        name = self.fake_names.get(pc, "?")
        v = self.FAKE_RET.get(name, "H")
        if v == "H":
            v = self.alloc(0x100)
            uc.mem_write(v, b"\0" * 0x100)
        self.log.append(f"CALL resolved API {name} -> {v:#x}")
        uc.reg_write(UC_ARM64_REG_X0, v)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _on_code(self, uc, address, size, _):
        if STUBS_LO <= address < STUBS_HI:
            base = address - ((address - STUBS_LO) % 12) if False else address
            self._call(STUB_NAMES.get(base, f"stub@{base:#x}"))
            return
        if FAKE_BASE <= address < FAKE_BASE + FAKE_SIZE:
            self._fake_api(address)
            return
        if address == WATCH_W9_AT:
            self.hits["sp_9c"] = uc.reg_read(UC_ARM64_REG_W9) & 0xFFFFFFFF
        elif address == WATCH_KEY_AT:
            self.hits["key32_be"] = uc.reg_read(UC_ARM64_REG_W8) & 0xFFFFFFFF
            sp = uc.reg_read(UC_ARM64_REG_SP)
            self.hits["sp"] = sp
            uc.emu_stop()
        if self.trace:
            print(f"  {address:#x}")

    def run(self, start=0x100000694, limit=80_000_000):
        uc = self.uc
        sp = STACK_BASE + STACK_SIZE - 0x8000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_LR, 0x0)
        uc.reg_write(UC_ARM64_REG_X0, 1)          # argc
        argv = self.alloc(64)
        uc.mem_write(argv, struct.pack("<Q", 0))
        uc.reg_write(UC_ARM64_REG_X1, argv)
        try:
            uc.emu_start(start, 0xFFFFFFFFFFFFFFFF, count=limit)
        except UcError as e:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            self.hits["error"] = f"{e} @ pc={pc:#x}"
        return self.hits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slice", nargs="?", default="slice_arm64.bin",
                    help="arm64 slice of the loader (default: %(default)s)")
    a = ap.parse_args()

    data = pathlib.Path(a.slice).read_bytes()
    e = Emu(data)
    hits = e.run()

    print("=== emulation result ===")
    for k, v in hits.items():
        print(f"  {k:10} = {v if isinstance(v, str) else hex(v)}")
    print(f"\n  dlsym-resolved ({len(e.resolved)}): {e.resolved}")
    print("\n  log:")
    for l in e.log[:60]:
        print("   ", l)
    if "key32_be" in hits:
        kb = struct.pack("<I", hits["key32_be"])
        print(f"\n  >>> 4-byte password bytes: {kb.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
