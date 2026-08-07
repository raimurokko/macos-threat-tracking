#!/usr/bin/env python3
"""
Decrypt the freshfix stage-3 payload.

Chain, all of it recovered without running the sample:

  password  = 4 bytes at [sp+0xfc], produced by emulating the loader's own
              obfuscated arithmetic (see emulate_key.py). Equals seed[0:4]
              byte-reversed -- a compile-time constant, not a host value.
  dk        = PBKDF2-HMAC-SHA256(password, salt @ __DATA_CONST+0xa0,
                                 iterations = 98222, dklen = 32)
  per chunk = subkey  = HMAC(HMAC(zeros32, dk), "freshfix-frag"\0\0\0 || i || 01)
              nonce   = subkey[0:12]
              plain   = ChaCha20-Poly1305(dk, nonce).decrypt(ct || tag)

Six chunks, lengths from the table at 0x100005bf0, ciphertext/tag pointers from
the tables at 0x100018fb0 / 0x100018fe0.
"""

import argparse
import hashlib
import hmac
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from unicorn import *
from unicorn.arm64_const import *

PASSWORD = bytes.fromhex("cb962534")   # from emulate_key.py, reference build
ITERATIONS = 98222
SALT_OFF, LEN_TBL, PTR_TBL, TAG_TBL = 0x80A0, 0x5BF0, 0x18FB0, 0x18FE0
HMAC_FN = 0x1000036D4


def emulated_hmac(d, key, msg):
    """Run the loader's own routine at 0x36d4 so we can check it really is
    HMAC-SHA256 rather than assuming it."""
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x100000000, 0x20000)           # __TEXT + __DATA_CONST + __DATA
    uc.mem_write(0x100000000, d[:0x20000])
    uc.mem_map(0x200000000, 0x100000)          # stack
    uc.mem_map(0x300000000, 0x10000)           # scratch
    uc.mem_map(0x400000000, 0x1000)            # ___chkstk_darwin landing pad
    uc.mem_write(0x100008000, struct.pack("<Q", 0x400000000))

    def on_code(u, addr, size, _):
        # The routine calls memcpy/bzero through __stubs, which are unbound in
        # the file. Service them here so nothing reaches the stub helper.
        if addr == 0x400000000:                # stack probe: no-op, return
            pass
        elif addr == 0x100005828:              # _memcpy
            a0, a1, a2 = (u.reg_read(r) for r in (UC_ARM64_REG_X0,
                                                  UC_ARM64_REG_X1,
                                                  UC_ARM64_REG_X2))
            u.mem_write(a0, bytes(u.mem_read(a1, a2)))
            u.reg_write(UC_ARM64_REG_X0, a0)
        elif addr == 0x1000057E0:              # _bzero
            a0, a1 = (u.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1))
            u.mem_write(a0, b"\0" * a1)
        else:
            return
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, on_code)
    sp = 0x200000000 + 0x80000
    uc.mem_write(0x300000000, key)
    uc.mem_write(0x300001000, msg)
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X0, 0x300000000)
    uc.reg_write(UC_ARM64_REG_X1, len(key))
    uc.reg_write(UC_ARM64_REG_X2, 0x300001000)
    uc.reg_write(UC_ARM64_REG_X3, len(msg))
    uc.reg_write(UC_ARM64_REG_X4, 0x300002000)
    uc.reg_write(UC_ARM64_REG_LR, 0x100000000)  # return lands here -> stop
    uc.emu_start(HMAC_FN, 0x100000000, count=50_000_000)
    return bytes(uc.mem_read(0x300002000, 32))


def qwords(d, off, n):
    return [struct.unpack("<Q", d[off + 8 * i:off + 8 * i + 8])[0] for i in range(n)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("slice", nargs="?", default="slice_arm64.bin",
                    help="arm64 slice of the loader (default: %(default)s)")
    ap.add_argument("-o", "--out", default="payload_decrypted.bin",
                    help="where to write the plaintext (default: %(default)s)")
    ap.add_argument("--password", default=PASSWORD.hex(),
                    help="4-byte password as hex, from emulate_key.py "
                         "(default: %(default)s, the reference build)")
    a = ap.parse_args()

    d = pathlib.Path(a.slice).read_bytes()
    password = bytes.fromhex(a.password)
    out_path = pathlib.Path(a.out)

    # --- 1. is 0x36d4 HMAC-SHA256? ask the binary, do not assume -----------
    print("== verifying the loader's HMAC routine at 0x36d4 ==")
    ok = True
    for key, msg in ((b"\xcb\x96\x25\x34", b"abc"),
                     (b"\x00" * 32, bytes(range(64))),
                     (b"k" * 13, bytes(range(18)))):
        got = emulated_hmac(d, key, msg)
        exp = hmac.new(key, msg, hashlib.sha256).digest()
        same = got == exp
        ok &= same
        print(f"   key={len(key):>2}B msg={len(msg):>2}B  emulated={got[:8].hex()}…  "
              f"hmac-sha256={exp[:8].hex()}…  {'MATCH' if same else 'DIFFER'}")
    if not ok:
        print("   -> not HMAC-SHA256; aborting")
        return 1
    print("   -> confirmed HMAC-SHA256\n")

    # --- 2. key schedule ---------------------------------------------------
    salt = d[SALT_OFF:SALT_OFF + 32]
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, 32)
    print("== key schedule ==")
    print(f"   password   : {password.hex()}")
    print(f"   salt       : {salt.hex()}")
    print(f"   iterations : {ITERATIONS}")
    print(f"   dk         : {dk.hex()}\n")

    inner = hmac.new(b"\x00" * 32, dk, hashlib.sha256).digest()

    # --- 3. chunks ---------------------------------------------------------
    lens = qwords(d, LEN_TBL, 6)
    ptrs = qwords(d, PTR_TBL, 6)
    tags = qwords(d, TAG_TBL, 6)

    print("== chunks ==")
    out = bytearray()
    for i in range(6):
        info = b"freshfix-frag\x00\x00\x00" + bytes([i, 1])
        nonce = hmac.new(inner, info, hashlib.sha256).digest()[:12]
        ct_off, tag_off = ptrs[i] - 0x100000000, tags[i] - 0x100000000
        ct = d[ct_off:ct_off + lens[i]]
        tag = d[tag_off:tag_off + 16]
        try:
            pt = ChaCha20Poly1305(dk).decrypt(nonce, ct + tag, None)
            print(f"   chunk {i}: {lens[i]:>6} bytes  nonce={nonce.hex()}  OK")
            out += pt
        except Exception as e:
            print(f"   chunk {i}: {lens[i]:>6} bytes  nonce={nonce.hex()}  FAIL ({type(e).__name__})")
            return 1

    out_path.write_bytes(bytes(out))
    print(f"\n   wrote {len(out)} bytes -> {out_path}")
    print(f"   sha256 {hashlib.sha256(out).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
