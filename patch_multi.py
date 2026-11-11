#!/usr/bin/env python3
"""Patch Il2CppDumper Zygisk module to support multiple package names.

The .so is PIE (position-independent), so absolute addresses stored in a data
array would be wrong at runtime. Instead we store 32-bit signed offsets
(string_addr - array_base) in the array, and the stub computes the real string
address as array_base + offset. array_base itself is loaded via a PC-relative
instruction, so it is correctly relocated by the loader.
"""
import struct
from keystone import *

# Package list (13 entries)
PACKAGES = [
    "com.tencent.tmgp.habby.danke",
    "com.habby.danke.mi",
    "com.habby.danke.huawei",
    "com.habby.danke.honor",
    "com.habby.danke.aligames",
    "com.hd.xxdkhb.and",
    "com.habby.danke.nearme.gamecenter",
    "com.habby.danke.vivo",
    "com.habby.danke.bytedance.gamecenter",
    "com.habby.danke.m4399",
    "com.habby.danke.bilibili",
    "com.game.danke",
    "com.dxx.firenow",
]

# Per-architecture configuration
ARCHS = {
    'arm64-v8a': {
        'path': 'multi_pkg/zygisk/arm64-v8a.so',
        'strcmp_plt': 0x66d30,
        'call_addr': 0x21470,
        'pkg_load_addr': 0x2145c,
        'cave': 0x10aa8,
        'mode': 'arm64',
    },
    'armeabi-v7a': {
        'path': 'multi_pkg/zygisk/armeabi-v7a.so',
        'strcmp_plt': 0x34380,
        'call_addr': 0xf968,
        'cave': 0xd8ca,
        'mode': 'thumb',
    },
    'x86': {
        'path': 'multi_pkg/zygisk/x86.so',
        'strcmp_plt': 0x67d60,
        'call_addr': 0x1cd76,
        'pkg_load_addr': 0x1cd6e,
        'cave': 0x9020,
        'mode': 'x86',
    },
    'x86_64': {
        'path': 'multi_pkg/zygisk/x86_64.so',
        'strcmp_plt': 0x6b6b0,
        'call_addr': 0x257c0,
        'pkg_load_addr': 0x257b6,
        'cave': 0x10680,
        'mode': 'x86_64',
    },
}


def build_strings():
    """Build concatenated NUL-terminated package strings."""
    strings = b''
    for pkg in PACKAGES:
        strings += pkg.encode('utf-8') + b'\x00'
    return strings


def build_offset_array(array_addr, strings_addr):
    """Build array of 32-bit signed offsets (string - array_base), terminated by 0."""
    arr = b''
    cur = strings_addr
    for pkg in PACKAGES:
        offset = cur - array_addr
        arr += struct.pack('<i', offset)
        cur += len(pkg) + 1
    arr += struct.pack('<i', 0)  # terminator
    return arr


def patch_arm64(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings = build_strings()
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    # Stub: x0=process, x1=array_base
    # Uses x21 as array_base, x20 as cursor.
    stub_asm = f"""
        stp x29, x30, [sp, #-0x30]!
        mov x29, sp
        stp x19, x20, [sp, #0x10]
        str x21, [sp, #0x20]
        mov x19, x0
        mov x21, x1
        mov x20, x1
    loop:
        ldr w2, [x20], #4
        cbz w2, nomatch
        add x1, x21, w2, sxtw
        mov x0, x19
        bl {hex(strcmp_plt)}
        cbz w0, match
        b loop
    match:
        mov w0, #0
        b exit
    nomatch:
        mov w0, #1
    exit:
        ldp x19, x20, [sp, #0x10]
        ldr x21, [sp, #0x20]
        ldp x29, x30, [sp], #0x30
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    # Array starts after stub, 4-byte aligned
    array_off = (stub_size + 3) & ~3
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * 4

    array_bytes = build_offset_array(array_addr, strings_addr)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch call site: adrp+add so x1 = array_addr
    page = array_addr & ~0xFFF
    off = array_addr & 0xFFF
    patch_bytes, _ = ks.asm(f'adrp x1, {hex(page)}; add x1, x1, {hex(off)}'.encode(), addr=cfg['pkg_load_addr'])
    patch_bytes = bytes(patch_bytes)
    data[0x2145c:0x2145c + 4] = patch_bytes[0:4]
    data[0x21464:0x21464 + 4] = patch_bytes[4:8]

    # bl strcmp -> bl stub
    bl_bytes, _ = ks.asm(f'bl {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 4] = bytes(bl_bytes)

    open(path, 'wb').write(data)
    print(f'arm64: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_arm32(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings = build_strings()
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    # Stub: r0=process, r1=array_base
    # Uses r6 as array_base, r5 as cursor.
    stub_asm = f"""
        push {{r4, r5, r6, lr}}
        mov r4, r0
        mov r6, r1
        mov r5, r1
    loop:
        ldr r2, [r5], #4
        cbz r2, nomatch
        add r1, r6, r2
        mov r0, r4
        blx {hex(strcmp_plt)}
        cbz r0, match
        b loop
    match:
        movs r0, #0
        b exit
    nomatch:
        movs r0, #1
    exit:
        pop {{r4, r5, r6, pc}}
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    array_off = (stub_size + 3) & ~3
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * 4

    array_bytes = build_offset_array(array_addr, strings_addr)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch literal pool so ldr+add resolves r1 = array_addr
    literal = (array_addr - 0xf968) & 0xFFFFFFFF
    data[0xf9bc:0xf9bc + 4] = struct.pack('<I', literal)

    # blx strcmp -> bl stub (Thumb->Thumb, use bl)
    bl_bytes, _ = ks.asm(f'bl {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 4] = bytes(bl_bytes)

    open(path, 'wb').write(data)
    print(f'arm32: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_x86(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings = build_strings()
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    # Stub: [esp+4]=process, [esp+8]=array_base (cdecl)
    # Uses esi=process, edi=cursor, edx=array_base
    stub_asm = f"""
        push ebp
        mov ebp, esp
        push esi
        push edi
        push edx
        mov esi, [ebp + 8]
        mov edx, [ebp + 12]
        mov edi, edx
    loop:
        mov eax, [edi]
        add edi, 4
        test eax, eax
        jz nomatch
        lea ecx, [edx + eax]
        push ecx
        push esi
        call {hex(strcmp_plt)}
        add esp, 8
        test eax, eax
        jz match
        jmp loop
    match:
        xor eax, eax
        jmp exit
    nomatch:
        mov eax, 1
    exit:
        pop edx
        pop edi
        pop esi
        pop ebp
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    array_off = (stub_size + 3) & ~3
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * 4

    array_bytes = build_offset_array(array_addr, strings_addr)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch: lea eax, [ebx-0x65b38] -> mov eax, array_addr; nop
    patch, _ = ks.asm(f'mov eax, {hex(array_addr)}'.encode(), addr=cfg['pkg_load_addr'])
    patch = bytes(patch) + b'\x90'
    data[cfg['pkg_load_addr']:cfg['pkg_load_addr'] + 6] = patch

    # call strcmp -> call stub
    call_bytes, _ = ks.asm(f'call {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 5] = bytes(call_bytes)

    open(path, 'wb').write(data)
    print(f'x86: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_x86_64(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings = build_strings()
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Stub: rdi=process, rsi=array_base
    # Uses r12=process, r13=cursor, r14=array_base
    stub_asm = f"""
        push rbp
        mov rbp, rsp
        push r12
        push r13
        push r14
        mov r12, rdi
        mov r14, rsi
        mov r13, rsi
    loop:
        movsxd rsi, dword ptr [r13]
        add r13, 4
        test rsi, rsi
        jz nomatch
        add rsi, r14
        mov rdi, r12
        call {hex(strcmp_plt)}
        test eax, eax
        jz match
        jmp loop
    match:
        xor eax, eax
        jmp exit
    nomatch:
        mov eax, 1
    exit:
        pop r14
        pop r13
        pop r12
        pop rbp
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    array_off = (stub_size + 3) & ~3
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * 4

    array_bytes = build_offset_array(array_addr, strings_addr)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch: lea rsi,[rip-0x18923]; mov rdi,rbx -> mov rsi,array_addr; mov rdi,rbx
    patch, _ = ks.asm(f'mov rsi, {hex(array_addr)}; mov rdi, rbx'.encode(), addr=cfg['pkg_load_addr'])
    assert len(patch) == 10, f'x86_64 patch is {len(patch)} bytes, expected 10'
    data[cfg['pkg_load_addr']:cfg['pkg_load_addr'] + 10] = bytes(patch)

    # call strcmp -> call stub
    call_bytes, _ = ks.asm(f'call {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 5] = bytes(call_bytes)

    open(path, 'wb').write(data)
    print(f'x86_64: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def main():
    for name, cfg in ARCHS.items():
        if cfg['mode'] == 'arm64':
            patch_arm64(cfg)
        elif cfg['mode'] == 'thumb':
            patch_arm32(cfg)
        elif cfg['mode'] == 'x86':
            patch_x86(cfg)
        elif cfg['mode'] == 'x86_64':
            patch_x86_64(cfg)


if __name__ == '__main__':
    main()
