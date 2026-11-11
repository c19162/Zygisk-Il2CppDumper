#!/usr/bin/env python3
"""Patch Il2CppDumper Zygisk module to support multiple package names."""
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
        'call_addr': 0x21470,       # bl strcmp
        'pkg_load_addr': 0x2145c,   # adrp x1, 0xd000
        'pkg_load_size': 0x10,      # 4 instructions (adrp, mov, add, mov)
        'cave': 0x10aa8,            # aligned cave start
        'ptr_size': 8,
        'mode': 'arm64',
    },
    'armeabi-v7a': {
        'path': 'multi_pkg/zygisk/armeabi-v7a.so',
        'strcmp_plt': 0x34380,
        'call_addr': 0xf968,        # blx strcmp
        'pkg_load_addr': 0xf95e,    # ldr r1, [pc, #0x5c]
        'pkg_load_size': 0xa,       # ldr(2) + mov(2) + mov(2) + add(2) + mov(2)
        'cave': 0xd8ca,             # 2-byte aligned for Thumb
        'ptr_size': 4,
        'mode': 'thumb',
    },
    'x86': {
        'path': 'multi_pkg/zygisk/x86.so',
        'strcmp_plt': 0x67d60,
        'call_addr': 0x1cd76,       # call strcmp
        'pkg_load_addr': 0x1cd6e,   # lea eax, [ebx - 0x65b38]
        'pkg_load_size': 0x8,       # lea(6) + push eax(1) + push esi(1)
        'cave': 0x9020,             # 4-byte aligned
        'ptr_size': 4,
        'mode': 'x86',
    },
    'x86_64': {
        'path': 'multi_pkg/zygisk/x86_64.so',
        'strcmp_plt': 0x6b6b0,
        'call_addr': 0x257c0,       # call strcmp
        'pkg_load_addr': 0x257b6,   # lea rsi, [rip - 0x18923]
        'pkg_load_size': 0xa,       # lea(7) + mov rdi,rbx(3)
        'cave': 0x10680,            # 8-byte aligned
        'ptr_size': 8,
        'mode': 'x86_64',
    },
}


def build_strings_and_array(ptr_size):
    """Build the concatenated strings and pointer array.
    Returns (strings_bytes, array_bytes, string_addresses).
    string_addresses are offsets from the start of the strings block."""
    strings = b''
    offsets = []
    for pkg in PACKAGES:
        offsets.append(len(strings))
        strings += pkg.encode('utf-8') + b'\x00'
    # Build array of pointers (will be fixed up with actual addresses later)
    return strings, offsets


def patch_arm64(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    ptr_size = cfg['ptr_size']
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings, str_offsets = build_strings_and_array(ptr_size)

    # Layout: [stub][aligned array][strings]
    # Assemble stub first to know its size
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    # We need array addr for the stub caller, but stub doesn't need it directly.
    # Stub: x0=process, x1=array_ptr
    stub_asm = f"""
        stp x29, x30, [sp, #-0x20]!
        mov x29, sp
        str x19, [sp, #0x10]
        str x20, [sp, #0x18]
        mov x19, x0
        mov x20, x1
    loop:
        ldr x1, [x20], #8
        cbz x1, nomatch
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
        ldr x19, [sp, #0x10]
        ldr x20, [sp, #0x18]
        ldp x29, x30, [sp], #0x20
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    # Array starts after stub, aligned to ptr_size
    array_off = (stub_size + ptr_size - 1) & ~(ptr_size - 1)
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * ptr_size

    # Build array with absolute pointers
    array_bytes = b''
    for off in str_offsets:
        array_bytes += struct.pack('<Q', strings_addr + off)
    array_bytes += struct.pack('<Q', 0)  # null terminator

    # Write stub + array + strings to cave
    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch call site: load array address into x1, then bl stub
    # Original:
    #   2145c: adrp x1, 0xd000
    #   21460: mov x20, x0
    #   21464: add x1, x1, #0x666
    #   21468: mov x0, x21
    #   2146c: mov x19, x2
    #   21470: bl strcmp
    # We need x1 = array_addr. Replace adrp+add with new adrp+add.
    # Keep mov x20, x0 (between them) and the rest.
    page = array_addr & ~0xFFF
    off = array_addr & 0xFFF
    patch_asm = f"""
        adrp x1, {hex(page)}
        add x1, x1, {hex(off)}
    """
    patch_bytes, _ = ks.asm(patch_asm.encode(), addr=cfg['pkg_load_addr'])
    patch_bytes = bytes(patch_bytes)
    # Write the new adrp+add (8 bytes) at 0x2145c and 0x21464
    # The original adrp is at 0x2145c (4 bytes), add at 0x21464 (4 bytes)
    # patch_bytes = [adrp(4), add(4)]
    data[0x2145c:0x2145c + 4] = patch_bytes[0:4]
    data[0x21464:0x21464 + 4] = patch_bytes[4:8]

    # Patch bl strcmp -> bl stub
    bl_bytes, _ = ks.asm(f'bl {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 4] = bytes(bl_bytes)

    open(path, 'wb').write(data)
    print(f'arm64: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_arm32(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    ptr_size = cfg['ptr_size']
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings, str_offsets = build_strings_and_array(ptr_size)

    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    # Stub: r0=process, r1=array_ptr
    stub_asm = f"""
        push {{r4, r5, r6, lr}}
        mov r4, r0
        mov r5, r1
    loop:
        ldr r1, [r5], #4
        cbz r1, nomatch
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

    array_off = (stub_size + ptr_size - 1) & ~(ptr_size - 1)
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * ptr_size

    array_bytes = b''
    for off in str_offsets:
        array_bytes += struct.pack('<I', strings_addr + off)
    array_bytes += struct.pack('<I', 0)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch call site:
    # Original:
    #   f95e: ldr r1, [pc, #0x5c]   ; loads literal from pool at 0xf9bc
    #   f960: mov r5, r0
    #   f962: mov r0, r6
    #   f964: add r1, pc            ; r1 = literal + PC(=0xf968) -> pkg string addr
    #   f966: mov r4, r2
    #   f968: blx strcmp
    # We keep the ldr+add instructions intact and only overwrite the 4-byte
    # literal pool entry at 0xf9bc so that r1 resolves to array_addr.
    # literal = (array_addr - 0xf968) & 0xFFFFFFFF
    literal = (array_addr - 0xf968) & 0xFFFFFFFF
    data[0xf9bc:0xf9bc + 4] = struct.pack('<I', literal)

    # Patch blx strcmp -> bl stub (both are Thumb, so bl is correct)
    bl_bytes, _ = ks.asm(f'bl {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 4] = bytes(bl_bytes)

    open(path, 'wb').write(data)
    print(f'arm32: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_x86(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    ptr_size = cfg['ptr_size']
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings, str_offsets = build_strings_and_array(ptr_size)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    # Stub: [esp+4]=process, [esp+8]=array_ptr (cdecl)
    # Actually for x86 cdecl: args on stack. arg1=process at [esp+4], arg2=array at [esp+8]
    stub_asm = f"""
        push ebp
        mov ebp, esp
        push esi
        push edi
        mov esi, [ebp + 8]
        mov edi, [ebp + 12]
    loop:
        mov eax, [edi]
        add edi, 4
        test eax, eax
        jz nomatch
        push eax
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
        pop edi
        pop esi
        pop ebp
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    array_off = (stub_size + ptr_size - 1) & ~(ptr_size - 1)
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * ptr_size

    array_bytes = b''
    for off in str_offsets:
        array_bytes += struct.pack('<I', strings_addr + off)
    array_bytes += struct.pack('<I', 0)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch call site:
    # Original:
    #   1cd6e: lea eax, [ebx - 0x65b38]   ; 6 bytes: 8d 83 c8 a4 f9 ff
    #   1cd74: push eax                    ; 1 byte
    #   1cd75: push esi                    ; 1 byte
    #   1cd76: call strcmp                 ; 5 bytes
    # We need eax = array_addr. Replace lea with mov eax, imm32 (5 bytes).
    # But lea is 6 bytes, mov eax,imm32 is 5 bytes + 1 nop = 6 bytes.
    patch, _ = ks.asm(f'mov eax, {hex(array_addr)}'.encode(), addr=cfg['pkg_load_addr'])
    patch = bytes(patch) + b'\x90'  # pad to 6 bytes with nop
    data[cfg['pkg_load_addr']:cfg['pkg_load_addr'] + 6] = patch

    # Patch call strcmp -> call stub
    call_bytes, _ = ks.asm(f'call {hex(cave)}'.encode(), addr=cfg['call_addr'])
    data[cfg['call_addr']:cfg['call_addr'] + 5] = bytes(call_bytes)

    open(path, 'wb').write(data)
    print(f'x86: stub@{hex(cave)}({stub_size}B) array@{hex(array_addr)} strings@{hex(strings_addr)}')


def patch_x86_64(cfg):
    path = cfg['path']
    data = bytearray(open(path, 'rb').read())
    ptr_size = cfg['ptr_size']
    cave = cfg['cave']
    strcmp_plt = cfg['strcmp_plt']

    strings, str_offsets = build_strings_and_array(ptr_size)

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Stub: rdi=process, rsi=array_ptr
    stub_asm = f"""
        push rbp
        mov rbp, rsp
        push r12
        push r13
        mov r12, rdi
        mov r13, rsi
    loop:
        mov rsi, [r13]
        add r13, 8
        test rsi, rsi
        jz nomatch
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
        pop r13
        pop r12
        pop rbp
        ret
    """
    stub_bytes, _ = ks.asm(stub_asm.encode(), addr=cave)
    stub_bytes = bytes(stub_bytes)
    stub_size = len(stub_bytes)

    array_off = (stub_size + ptr_size - 1) & ~(ptr_size - 1)
    array_addr = cave + array_off
    strings_addr = array_addr + (len(PACKAGES) + 1) * ptr_size

    array_bytes = b''
    for off in str_offsets:
        array_bytes += struct.pack('<Q', strings_addr + off)
    array_bytes += struct.pack('<Q', 0)

    data[cave:cave + stub_size] = stub_bytes
    data[array_addr:array_addr + len(array_bytes)] = array_bytes
    data[strings_addr:strings_addr + len(strings)] = strings

    # Patch call site:
    # Original:
    #   257b6: lea rsi, [rip - 0x18923]  ; 7 bytes: 48 8d 35 d7 76 fe ff
    #   257bd: mov rdi, rbx               ; 3 bytes: 48 89 df
    #   257c0: call strcmp                ; 5 bytes
    # We need rsi = array_addr. Replace lea(7) + mov rdi,rbx(3) = 10 bytes
    # with mov rsi, imm32(7) + mov rdi, rbx(3) = 10 bytes.
    patch, _ = ks.asm(f'mov rsi, {hex(array_addr)}; mov rdi, rbx'.encode(), addr=cfg['pkg_load_addr'])
    assert len(patch) == 10, f'x86_64 patch is {len(patch)} bytes, expected 10'
    data[cfg['pkg_load_addr']:cfg['pkg_load_addr'] + 10] = bytes(patch)

    # Patch call strcmp -> call stub
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
