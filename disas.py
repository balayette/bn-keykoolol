from binaryninja.function import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LLIL_TEMP, ILIntrinsic, ILRegister
from binaryninja.log import *


def tI(x):
    return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)


def tR(x):
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)


def tS(x):
    return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)


def tM(x):
    return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)


def tE(x):
    return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)


def tA(x, d):
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)


def tT(x):
    return InstructionTextToken(InstructionTextTokenType.TextToken, x)


def tN(x, d):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)


def h_inc(bs, eip):
    dis = (bs >> 0x14) & 0xF
    return [tI("inc"), tT(" "), tR(f"r{dis}")]


def h_sub_imm(bs, eip):
    cl = (bs >> 0xC) & 0xFF
    eax = (bs >> 0x14) & 0xF
    return [tI("sub"), tT(" "), tR(f"r{eax}"), tS(","), tN(hex(cl), cl)]


def h_cmp_imm(bs, eip):
    dis = (bs >> 0x14) & 0xF
    cl = (bs >> 0xC) & 0xFF
    return [
        tI("cmp"),
        tT(" "),
        tR(f"r{dis}"),
        tS(","),
        tN(hex(cl), cl),
    ]


def h_if_zero(bs, eip):
    dst = bs & 0xFFFFFF
    return [tI("jz"), tT(" "), tA(hex(dst), dst)]


def h_if_not_zero(bs, eip):
    dst = bs & 0xFFFFFF
    return [tI("jnz"), tT(" "), tA(hex(dst), dst)]


def h_jg(bs, eip):
    dst = bs & 0xFFFFFF
    return [tI("jg"), tT(" "), tA(hex(dst), dst)]


def h_jl(bs, eip):
    dst = bs & 0xFFFFFF
    return [tI("jl"), tT(" "), tA(hex(dst), dst)]


def h_ass_r(bs, eip):
    src = (bs >> 0x10) & 0xF
    dst = bs >> 0x14
    return [tI("mov"), tT(" "), tR(f"r{dst}"), tS(","), tR(f"r{src}")]


def h_call(bs, eip):
    ne = bs & 0xFFFFFF
    return [tI("call"), tT(" "), tA(hex(ne), ne)]


def h_ass_imm(bs, eip):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF
    return [tI("mov"), tT(" "), tR(f"r{dst}"), tS(","), tN(hex(val), val)]


def h_finish(bs, eip):
    return [tI(f"exit")]


def h_add_imm(bs, eip):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF
    return [tI("add"), tT(" "), tR(f"r{dst}"), tS(","), tN(hex(val), val)]


def h_lip(bs, eip):
    dst = (bs >> 0x14) & 0xF
    return [tI("lip"), tT(" "), tR(f"r{dst}")]


def h_jump(bs, eip):
    dst = bs & 0xFFFFFF
    return [tI("jmp"), tT(" "), tA(hex(dst), dst)]


def h_xor_imm(bs, eip):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return [tI("xor"), tT(" "), tR(f"r{dst}"), tS(","), tN(hex(val), val)]


def h_shl(bs, eip):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return [tI("shl"), tT(" "), tR(f"r{dst}"), tS(","), tN(hex(val), val)]


def h_shr(bs, eip):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return [tI("shr"), tT(" "), tR(f"r{dst}"), tS(","), tN(hex(val), val)]


def h_xor(bs, eip):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return [tI("xor"), tT(" "), tR(f"r{dst}"), tS(","), tR(f"r{src}")]


def h_add(bs, eip):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return [tI("add"), tT(" "), tR(f"r{dst}"), tS(","), tR(f"r{src}")]


def h_load_bswap(bs, eip):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return [
        tI("bswap"),
        tT(" "),
        tR(f"r{dst}"),
        tS(","),
        tM("dword ["),
        tR(f"r{src}"),
        tE("]"),
    ]


def h_store_bswap(bs, eip):
    dst = (bs >> 0x14) & 0xF
    src = (bs >> 0x10) & 0xF

    return [
        tI("bswap"),
        tT(" "),
        tM("dword ["),
        tR(f"r{dst}"),
        tE("]"),
        tS(","),
        tR(f"r{src}"),
    ]


def h_ret(bs, eip):
    return [tI("ret")]


def h_load_byte(bs, eip):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return [
        tI("mov"),
        tT(" "),
        tR(f"r{dst}"),
        tS(","),
        tM("byte ["),
        tR(f"r{src}"),
        tE("]"),
    ]


def h_mod(bs, eip):
    divisor = (bs >> 0xC) & 0xFF
    src = (bs >> 0x14) & 0xF

    return [tI("mod"), tT(" "), tR(f"r{src}"), tS(","), tN(hex(divisor), divisor)]


def h_mul(bs, eip):
    src = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return [tI("mul"), tT(" "), tR(f"r{src}"), tS(","), tN(hex(val), val)]


def h_store(bs, eip):
    dst = (bs >> 0x14) & 0xF
    src = (bs >> 0x10) & 0xF

    return [
        tI("mov"),
        tT(" "),
        tM("byte ["),
        tR(f"r{dst}"),
        tE("]"),
        tS(","),
        tR(f"r{src}"),
    ]


def h_aes(bs, eip):
    val_src = (bs >> 0x10) & 0xF  # xmm0 = mem1[r[val_src]] (16 bytes)
    key_src = (bs >> 0xC) & 0xF  # xmm1 = mem1[r[key_src]] (16 bytes)
    # xmm0 = aes(val=xmm0, key=xmm1)
    dst = (bs >> 0x14) & 0xF  # mem16[r[dst]] = xmm0

    return [
        tI("aes"),
        tT(" "),
        tM("xmmword ["),
        tR(f"r{dst}"),
        tE("]"),
        tS(","),
        tM("xmmword ["),
        tR(f"r{val_src}"),
        tE("]"),
        tS(","),
        tM("xmmword ["),
        tR(f"r{key_src}"),
        tE("]"),
    ]


def h_cmp_r(bs, eip):
    l = (bs >> 0x14) & 0xF
    r = (bs >> 0x10) & 0xF

    return [tI("cmp"), tT(" "), tR(f"r{l}"), tS(","), tR(f"r{r}")]


handlers = {
    0x0: h_ass_r,
    0x1: h_load_byte,
    0x2: h_ass_imm,
    0x3: h_store,
    0x6: h_call,
    0x7: h_cmp_r,
    0x8: h_cmp_imm,
    0x9: h_if_zero,
    0xA: h_if_not_zero,
    0xB: h_add,
    0xC: h_add_imm,
    0xE: h_mul,
    0xF: h_inc,
    0x11: h_mod,
    0x12: h_xor,
    0x13: h_xor_imm,
    0x14: h_jl,
    0x15: h_jg,
    0x17: h_sub_imm,
    0x18: h_jump,
    0x19: h_shr,
    0x1A: h_lip,
    0x1B: h_load_bswap,
    0x1C: h_store_bswap,
    0x1D: h_shl,
    0x1E: h_aes,
    0xFE: h_ret,
    0xFF: h_finish,
}


def disas(data, addr):
    op = int.from_bytes(data, byteorder="little")
    opc = (op >> 0x18) & 0xFF
    if opc not in handlers:
        return [tT("UNKNOWN INSTRUCTION")], 4
    h = handlers[opc]
    return h(op, addr), 4


def disas_info(data, addr):
    d = int.from_bytes(data, byteorder="little")
    op = d >> 0x18
    h = handlers[(op >> 0x18) & 0xFF]
    if h is None:
        return None

    res = InstructionInfo()
    res.length = 4

    if op == 0xFE or op == 0xFF:
        res.add_branch(BranchType.FunctionReturn)
    if op == 0x18:
        res.add_branch(BranchType.UnconditionalBranch, d & 0xFFFFFF)
    if op == 0x6:
        res.add_branch(BranchType.CallDestination, d & 0xFFFFFF)
    if op == 0x15 or op == 0x14 or op == 0xA or op == 0x9:
        res.add_branch(BranchType.TrueBranch, d & 0xFFFFFF)
        res.add_branch(BranchType.FalseBranch, addr + 4)

    return res


def lab(addr, il):
    l = il.get_label_for_address(Architecture["Keykoo"], addr)
    if l is not None:
        return l
    il.add_label_for_address(Architecture["Keykoo"], addr)
    l = lab(addr, il)
    # no idea what mark_label does, but BN complains sometimes... Maybe add it
    # here?
    return l


def il_sub_imm(bs, addr, il):
    cl = (bs >> 0xC) & 0xFF
    eax = (bs >> 0x14) & 0xF

    return il.set_reg(4, f"r{eax}", il.sub(4, il.reg(4, f"r{eax}"), il.const(4, cl)))


def il_cmp_imm(bs, addr, il):
    dis = (bs >> 0x14) & 0xF
    cl = (bs >> 0xC) & 0xFF

    return il.set_reg(4, "rc", il.sub(4, il.reg(4, f"r{dis}"), il.const(4, cl)))


def il_jnz(bs, addr, il):
    return il.if_expr(
        il.compare_not_equal(4, il.reg(4, "rc"), il.const(4, 0)),
        lab(bs & 0xFFFFFF, il),
        lab(addr + 4, il),
    )


def il_jz(bs, addr, il):
    return il.if_expr(
        il.compare_equal(4, il.reg(4, "rc"), il.const(4, 0)),
        lab(bs & 0xFFFFFF, il),
        lab(addr + 4, il),
    )


def il_jl(bs, addr, il):
    return il.if_expr(
        il.compare_signed_less_than(4, il.reg(4, "rc"), il.const(4, 0)),
        lab(bs & 0xFFFFFF, il),
        lab(addr + 4, il),
    )


def il_jg(bs, addr, il):
    return il.if_expr(
        il.compare_signed_greater_than(4, il.reg(4, "rc"), il.const(4, 0)),
        lab(bs & 0xFFFFFF, il),
        lab(addr + 4, il),
    )


def il_jump(bs, addr, il):
    dst = bs & 0xFFFFFF

    return il.goto(lab(dst, il))


def il_ass_r(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return il.set_reg(4, f"r{dst}", il.reg(4, f"r{src}"))


def il_call(bs, addr, il):
    ne = bs & 0xFFFFFF
    return il.call(il.const(4, ne))


def il_add(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return il.set_reg(
        4, f"r{dst}", il.add(4, il.reg(4, f"r{dst}"), il.reg(4, f"r{src}"))
    )


def il_add_imm(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(4, f"r{dst}", il.add(4, il.reg(4, f"r{dst}"), il.const(4, val)))


def il_ass_imm(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(4, f"r{dst}", il.const(4, val))


def il_ret(bs, addr, il):
    return il.ret(il.pop(4))


def il_finish(bs, addr, il):
    return il.trap(0)


def il_load_byte(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return il.set_reg(4, f"r{dst}", il.load(1, il.reg(4, f"r{src}")))


def il_inc(bs, addr, il):
    dis = (bs >> 0x14) & 0xF

    return il.set_reg(4, f"r{dis}", il.add(4, il.reg(4, f"r{dis}"), il.const(4, 1)))


def il_store(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    src = (bs >> 0x10) & 0xF

    return il.store(1, il.reg(4, f"r{dst}"), il.reg(4, f"r{src}"))


def il_mod(bs, addr, il):
    divisor = (bs >> 0xC) & 0xFF
    src = (bs >> 0x14) & 0xF

    return il.set_reg(
        4, f"r{src}", il.mod_signed(4, il.reg(4, f"r{src}"), il.const(4, divisor))
    )


def il_mul(bs, addr, il):
    src = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(4, f"r{src}", il.mult(4, il.reg(4, f"r{src}"), il.const(4, val)))


def il_shr(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(
        4, f"r{dst}", il.logical_shift_right(4, il.reg(4, f"r{dst}"), il.const(4, val))
    )


def il_shl(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(
        4, f"r{dst}", il.shift_left(4, il.reg(4, f"r{dst}"), il.const(4, val))
    )


def il_xor(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    return il.set_reg(
        4, f"r{dst}", il.xor_expr(4, il.reg(4, f"r{dst}"), il.reg(4, f"r{src}"))
    )


def il_xor_imm(bs, addr, il):
    dst = (bs >> 0x14) & 0xF
    val = (bs >> 0xC) & 0xFF

    return il.set_reg(
        4, f"r{dst}", il.xor_expr(4, il.reg(4, f"r{dst}"), il.const(4, val))
    )


def il_lip(bs, addr, il):
    dst = (bs >> 0x14) & 0xF

    return il.set_reg(4, f"r{dst}", il.const(4, addr + 4))


def il_load_bswap(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    t0 = LLIL_TEMP(0)
    t1 = LLIL_TEMP(1)
    t2 = LLIL_TEMP(2)
    t3 = LLIL_TEMP(3)

    load = il.set_reg(4, f"r{dst}", il.load(4, il.reg(4, f"r{src}")))
    dreg = il.reg(4, f"r{dst}")

    t0e = il.set_reg(
        4,
        t0,
        il.shift_left(4, il.and_expr(4, dreg, il.const(4, 0xFF)), il.const(4, 0x18)),
    )
    t1e = il.set_reg(
        4,
        t1,
        il.shift_left(4, il.and_expr(4, dreg, il.const(4, 0xFF00)), il.const(4, 0x8)),
    )
    t2e = il.set_reg(
        4,
        t2,
        il.logical_shift_right(
            4, il.and_expr(4, dreg, il.const(4, 0xFF0000)), il.const(4, 0x8)
        ),
    )
    t3e = il.set_reg(
        4,
        t3,
        il.logical_shift_right(
            4, il.and_expr(4, dreg, il.const(4, 0xFF000000)), il.const(4, 0x18)
        ),
    )

    fin = il.set_reg(
        4,
        f"r{dst}",
        il.or_expr(
            4,
            il.or_expr(4, il.or_expr(4, il.reg(4, t2), il.reg(4, t3)), il.reg(4, t1)),
            il.reg(4, t0),
        ),
    )

    il.append(load)
    il.append(t0e)
    il.append(t1e)
    il.append(t2e)
    il.append(t3e)

    return fin


def il_store_bswap(bs, addr, il):
    src = (bs >> 0x10) & 0xF
    dst = (bs >> 0x14) & 0xF

    t0 = LLIL_TEMP(0)
    t1 = LLIL_TEMP(1)
    t2 = LLIL_TEMP(2)
    t3 = LLIL_TEMP(3)

    sreg = il.reg(4, f"r{src}")

    t0e = il.set_reg(
        4,
        t0,
        il.shift_left(4, il.and_expr(4, sreg, il.const(4, 0xFF)), il.const(4, 0x18)),
    )
    t1e = il.set_reg(
        4,
        t1,
        il.shift_left(4, il.and_expr(4, sreg, il.const(4, 0xFF00)), il.const(4, 0x8)),
    )
    t2e = il.set_reg(
        4,
        t2,
        il.logical_shift_right(
            4, il.and_expr(4, sreg, il.const(4, 0xFF0000)), il.const(4, 0x8)
        ),
    )
    t3e = il.set_reg(
        4,
        t3,
        il.logical_shift_right(
            4, il.and_expr(4, sreg, il.const(4, 0xFF000000)), il.const(4, 0x18)
        ),
    )

    il.append(t0e)
    il.append(t1e)
    il.append(t2e)
    il.append(t3e)

    return il.store(
        4,
        il.reg(4, f"r{dst}"),
        il.or_expr(
            4,
            il.or_expr(4, il.or_expr(4, il.reg(4, t2), il.reg(4, t3)), il.reg(4, t1)),
            il.reg(4, t0),
        ),
    )


def il_cmp_r(bs, addr, il):
    l = (bs >> 0x14) & 0xF
    r = (bs >> 0x10) & 0xF

    return il.set_reg(4, "rc", il.sub(4, il.reg(4, f"r{l}"), il.reg(4, f"r{r}")))


def il_aes(bs, addr, il):
    val_src = (bs >> 0x10) & 0xF  # xmm0 = mem1[r[val_src]] (16 bytes)
    key_src = (bs >> 0xC) & 0xF  # xmm1 = mem1[r[key_src]] (16 bytes)
    # xmm0 = aes(val=xmm0, key=xmm1)
    dst = (bs >> 0x14) & 0xF  # mem16[r[dst]] = xmm0

    enct = LLIL_TEMP(0)

    compute = il.intrinsic(
        [ILRegister(Architecture["Keykoo"], enct)],
        "__aes",
        [il.load(16, il.reg(4, f"r{key_src}")), il.load(16, il.reg(4, f"r{val_src}"))],
    )
    il.append(compute)

    return il.store(16, il.reg(4, f"r{dst}"), il.reg(16, enct))


il_handlers = {
    0x0: il_ass_r,
    0x1: il_load_byte,
    0x2: il_ass_imm,
    0x3: il_store,
    0x6: il_call,
    0x7: il_cmp_r,
    0x8: il_cmp_imm,
    0x9: il_jz,
    0xA: il_jnz,
    0xB: il_add,
    0xC: il_add_imm,
    0xE: il_mul,
    0xF: il_inc,
    0x11: il_mod,
    0x12: il_xor,
    0x13: il_xor_imm,
    0x14: il_jl,
    0x15: il_jg,
    0x17: il_sub_imm,
    0x18: il_jump,
    0x19: il_shr,
    0x1A: il_lip,
    0x1B: il_load_bswap,
    0x1C: il_store_bswap,
    0x1D: il_shl,
    0x1E: il_aes,
    0xFE: il_ret,
    0xFF: il_finish,
}


def disas_il(data, addr, il):
    d = int.from_bytes(data, byteorder="little")
    op = (d >> 0x18) & 0xFF
    if op not in il_handlers:
        il.append(il.unimplemented())
    else:
        il.append(il_handlers[op](d, addr, il))

    return 4
