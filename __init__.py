from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo
from binaryninja.callingconvention import CallingConvention

from .disas import *

class Keykoo(Architecture):
    name = "Keykoo"
    address_size = 4
    default_int_size = 4
    instr_alignment = 4
    max_instr_length = 4

    # gpr
    regs = {f"r{i}": RegisterInfo(f"r{i}", 4) for i in range(16)}
    # comparison register (%r9)
    regs["rc"] = RegisterInfo("rc", 4)
    regs["sp"] = RegisterInfo("sp", 4)

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):
        return disas_info(data, addr)

    def get_instruction_text(self, data, addr):
        i, l = disas(data, addr)
        if i is None:
            return [tT("unimplemented")], 4
        else:
            return i, l

    def get_instruction_low_level_il(self, data, addr, il):
        return disas_il(data, addr, il)


class KeykooCC(CallingConvention):
    name = "KeykooCC"
    int_arg_regs = [f"r{i}" for i in range(3)]
    int_return_reg = "r0"

Keykoo.register()
arch = Architecture['Keykoo']
arch.register_calling_convention(KeykooCC(arch, 'default'))
