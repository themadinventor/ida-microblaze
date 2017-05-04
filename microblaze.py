# IDAPython MicroBlaze processor module
# https://github.com/themadinventor/ida-microblaze
#
# Copyright (C) 2017 Fredrik Ahlberg
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

from idaapi import *


class Operand(object):

    REG = 0
    IMM = 1

    def __init__(self, type, size, bitidx, dt=dt_dword):
        self.type = type
        self.size = size
        self.bitidx = bitidx
        self.dt = dt

    def bitfield(self, op):
        return (op >> (32 - self.bitidx - self.size)) & (0xffffffff >> (32 - self.size))

    def parse(self, ret, op, cmd = None):
        val = self.bitfield(op)
        ret.dtyp = self.dt
        if self.type == Operand.REG:
            ret.type = o_reg
            ret.reg = val
        elif self.type == Operand.IMM:
            ret.type = o_imm
            ret.value = val
        else:
            raise ValueError('Unhandled operand type')


class Instr(object):

    fmt_3R = (Operand(Operand.REG, 5, 6), Operand(Operand.REG, 5, 11), Operand(Operand.REG, 5, 16))
    fmt_2R_IMM = (Operand(Operand.REG, 5, 6), Operand(Operand.REG, 5, 11), Operand(Operand.IMM, 16, 16))
    fmt_2R = (Operand(Operand.REG, 5, 6), Operand(Operand.REG, 5, 11))
    fmt_2R2 = (Operand(Operand.REG, 5, 11), Operand(Operand.REG, 5, 16))
    fmt_1R_IMM = (Operand(Operand.REG, 5, 11), Operand(Operand.IMM, 16, 16))
    fmt_1R2_IMM = (Operand(Operand.REG, 5, 6), Operand(Operand.IMM, 16, 16))
    fmt_1R_IMM14 = (Operand(Operand.REG, 5, 11), Operand(Operand.IMM, 14, 18))
    fmt_1R = (Operand(Operand.REG, 5, 11),)
    fmt_IMM = (Operand(Operand.IMM, 16, 16),)

    def __init__(self, mnem, opcode, mask, fmt, flags = 0):
        self.mnem = mnem
        self.opcode = opcode
        self.mask = mask
        self.fmt = fmt
        self.flags = flags

    def match(self, op):
        return (op & self.mask) == self.opcode

    def parseOperands(self, operands, op, cmd = None):
        for ret, fmt in zip(operands, self.fmt):
            fmt.parse(ret, op, cmd)


class MicroBlazeProcessor(processor_t):

    id = 0x8000 + 1993
    flag = PR_SEGS | PR_DEFSEG32 | PR_RNAMESOK | PR_ADJSEGS | PRN_HEX | PR_USE32
    cnbits = 8
    dnbits = 8
    psnames = ["xilmb"]
    plnames = ["Xilinx MicroBlaze"]
    segreg_size = 0
    tbyte_size = 0

    instruc_start = 0

    assembler = {
        "flag": ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_NOTAB
            | AS_ASCIIC | AS_ASCIIZ,
        "uflag": 0,
        "name": "GNU assembler",
        "origin": ".org",
        "end": "end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".short",
        "a_dword": ".int",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": ".",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extrn",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    ops = (
        ('add',         0x00000000, 0xfc0007ff, Instr.fmt_3R),
        ('rsub',        0x04000000, 0xfc0007ff, Instr.fmt_3R),
        ('addc',        0x08000000, 0xfc0007ff, Instr.fmt_3R),
        ('rsubc',       0x0c000000, 0xfc0007ff, Instr.fmt_3R),
        ('addk',        0x10000000, 0xfc0007ff, Instr.fmt_3R),
        ('rsubk',       0x14000000, 0xfc0007ff, Instr.fmt_3R),
        ('addkc',       0x18000000, 0xfc0007ff, Instr.fmt_3R),
        ('rsubkc',      0x1c000000, 0xfc0007ff, Instr.fmt_3R),
        ('cmp',         0x14000001, 0xfc0007ff, Instr.fmt_3R),
        ('cmpu',        0x14000003, 0xfc0007ff, Instr.fmt_3R),
        ('addi',        0x20000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('rsubi',       0x24000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('addic',       0x28000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('rsubic',      0x2c000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('addik',       0x30000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('rsubik',      0x34000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('addikc',      0x38000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('rsubikc',     0x3c000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('mul',         0x40000000, 0xfc0007ff, Instr.fmt_3R),
        ('mulh',        0x40000001, 0xfc0007ff, Instr.fmt_3R),
        ('mulhu',       0x40000003, 0xfc0007ff, Instr.fmt_3R),
        ('mulhsu',      0x40000002, 0xfc0007ff, Instr.fmt_3R),
        ('bsra',        0x44000000, 0xfc0007ff, Instr.fmt_3R),
        ('bsll',        0x44000400, 0xfc0007ff, Instr.fmt_3R),
        ('muli',        0x60000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('bsrli',       0x64000000, 0xfc00ffe0, Instr.fmt_2R_IMM),
        ('bsrai',       0x64000200, 0xfc00ffe0, Instr.fmt_2R_IMM),
        ('bslli',       0x64000400, 0xfc00ffe0, Instr.fmt_2R_IMM),
        ('idiv',        0x48000000, 0xfc0007ff, Instr.fmt_3R),
        ('idivu',       0x48000002, 0xfc0007ff, Instr.fmt_3R),
        #GETD
        #PUTD
        #CGETD
        #CPUTD
        #FADD
        #FRSUB
        #FMUL
        #FDIV
        #FCMP.UN
        #FCMP.LT
        #FCMP.EQ
        #FCMP.LE
        #FCMP.GT
        #FCMP.NE
        #FCMP.GE
        #FLT
        #FINT
        #FSQRT
        #GET
        #PUT
        #CGET
        #CPUT
        ('or',          0x80000000, 0xfc0007ff, Instr.fmt_3R),
        ('and',         0x84000000, 0xfc0007ff, Instr.fmt_3R),
        ('xor',         0x88000000, 0xfc0007ff, Instr.fmt_3R),
        ('andn',        0x8c000000, 0xfc0007ff, Instr.fmt_3R),
        ('pcmpbf',      0x80000400, 0xfc0007ff, Instr.fmt_3R),
        ('pcmpeq',      0x88000400, 0xfc0007ff, Instr.fmt_3R),
        ('pcmpne',      0x8c000400, 0xfc0007ff, Instr.fmt_3R),
        ('sra',         0x90000001, 0xfc00ffff, Instr.fmt_2R),
        ('src',         0x90000021, 0xfc00ffff, Instr.fmt_2R),
        ('srl',         0x90000041, 0xfc00ffff, Instr.fmt_2R),
        ('sext8',       0x90000060, 0xfc00ffff, Instr.fmt_2R),
        ('sext16',      0x90000061, 0xfc00ffff, Instr.fmt_2R),
        ('wic',         0x90000068, 0xfc00ffff, Instr.fmt_2R2), #WAT
        ('wdc',         0x90000064, 0xfc00ffff, Instr.fmt_2R2), #WAT
        ('mts',         0x9400c000, 0xfc00c000, Instr.fmt_1R_IMM14),
        ('mfs',         0x94008000, 0xfc00c000, Instr.fmt_1R_IMM14),
        ('msrclr',      0x94010000, 0xfc1fc000, Instr.fmt_1R_IMM14),
        ('msrset',      0x94000000, 0xfc1fc000, Instr.fmt_1R_IMM14),
        ('br',          0x98000000, 0xffff01ff, Instr.fmt_1R, CF_JUMP|CF_STOP),
        ('brd',         0x98100000, 0xffff01ff, Instr.fmt_1R, CF_JUMP|CF_STOP),
        ('brld',        0x98140000, 0xfc1f01ff, Instr.fmt_2R2, CF_CALL),
        ('bra',         0x98080000, 0xffff01ff, Instr.fmt_1R, CF_JUMP|CF_STOP),
        ('brad',        0x98180000, 0xffff01ff, Instr.fmt_1R, CF_JUMP|CF_STOP),
        ('brald',       0x981c0000, 0xfc1f01ff, Instr.fmt_2R2, CF_CALL),
        ('brk',         0x980c0000, 0xfc1f01ff, Instr.fmt_2R2, CF_CALL),

        ('beq',         0x9c000000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bne',         0x9c200000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('blt',         0x9c400000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('ble',         0x9c600000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bgt',         0x9c800000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bge',         0x9ca00000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('beqd',        0x9e000000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bned',        0x9e200000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bltd',        0x9e400000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bled',        0x9e600000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bgtd',        0x9e800000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),
        ('bged',        0x9ea00000, 0xfc0007ff, Instr.fmt_2R2, CF_JUMP),

        ('ori',         0xa0000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('andi',        0xa4000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('xori',        0xa8000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('andni',       0xac000000, 0xfc000000, Instr.fmt_2R_IMM),

        ('imm',         0xb0000000, 0xffff0000, Instr.fmt_IMM),

        ('rtsd',        0xb6000000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP|CF_STOP),
        ('rtid',        0xb6200000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP|CF_STOP),
        ('rtbd',        0xb6400000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP|CF_STOP),
        ('rted',        0xb6800000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP|CF_STOP),

        ('bri',         0xb8000000, 0xffff0000, Instr.fmt_IMM, CF_JUMP|CF_STOP),
        ('brid',        0xb8100000, 0xffff0000, Instr.fmt_IMM, CF_JUMP|CF_STOP),
        ('brlid',       0xb8140000, 0xfc1f0000, Instr.fmt_1R2_IMM, CF_JUMP),
        ('brai',        0xb8080000, 0xffff0000, Instr.fmt_IMM, CF_JUMP|CF_STOP),
        ('braid',       0xb8180000, 0xffff0000, Instr.fmt_IMM, CF_JUMP|CF_STOP),
        ('bralid',      0xb81c0000, 0xffff0000, Instr.fmt_1R2_IMM, CF_JUMP),
        ('brki',        0xb80c0000, 0xfc1f0000, Instr.fmt_1R2_IMM, CF_JUMP),

        ('beqi',        0xbc000000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bnei',        0xbc200000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('blti',        0xbc400000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('blei',        0xbc600000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bgti',        0xbc800000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bgei',        0xbca00000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('beqid',       0xbe000000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bneid',       0xbe200000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bltid',       0xbe400000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bleid',       0xbe600000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bgtid',       0xbe800000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),
        ('bgeid',       0xbea00000, 0xffe00000, Instr.fmt_1R_IMM, CF_JUMP),

        ('lbu',         0xc0000000, 0xfc0007ff, Instr.fmt_3R),
        ('lhu',         0xc4000000, 0xfc0007ff, Instr.fmt_3R),
        ('lw',          0xc8000000, 0xfc0007ff, Instr.fmt_3R),
        ('sb',          0xd0000000, 0xfc0007ff, Instr.fmt_3R),
        ('sh',          0xd4000000, 0xfc0007ff, Instr.fmt_3R),
        ('sw',          0xd8000000, 0xfc0007ff, Instr.fmt_3R),

        ('lbui',        0xe0000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('lhui',        0xe4000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('lwi',         0xe8000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('sbi',         0xf0000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('shi',         0xf4000000, 0xfc000000, Instr.fmt_2R_IMM),
        ('swi',         0xf8000000, 0xfc000000, Instr.fmt_2R_IMM),
    )

    def __init__(self):
        processor_t.__init__(self)
        self.__init_instructions()
        self.__init_registers()

    def __init_instructions(self):
        self.instrs_list = []
        for o in self.ops:
            instr = Instr(*o)
            self.instrs_list.append(instr)
        self.instruc = [{ "name": i.mnem, "feature": i.flags } for i in self.instrs_list]
        self.instruc_end = len(self.instruc)

        self.instrs = {}
        for instr in self.instrs_list:
            self.instrs[instr.mnem] = instr

        self.instrs_ids = {}
        for i, instr in enumerate(self.instrs_list):
            self.instrs_ids[instr.mnem] = i
            instr.id = i

    def __init_registers(self):
        self.regNames = ["r%d" % d for d in range(32)]
        self.regNames += ["pc", "msr", "ear", "esr", "ess", "btr", "fsr", "edr",
                "pid", "zpr", "tlblo", "tlbhi", "tlbx", "tlbsx", "pvr", "CS", "DS"]
        self.reg_ids = {}
        for i, reg in enumerate(self.regNames):
            self.reg_ids[reg] = 1
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def __pull_op_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_full_byte(ea)
        self.cmd.size += 1
        return byte

    def __find_instr(self):
        op = self.__pull_op_byte()
        op |= self.__pull_op_byte() << 8
        op |= self.__pull_op_byte() << 16
        op |= self.__pull_op_byte() << 24

        for instr in self.instrs_list:
            if instr.match(op):
                return instr, op

        print("no instruction found matching %08x" % op)
        return None, op

    def ana(self):
        instr, op = self.__find_instr()
        if not instr:
            return 0

        self.cmd.itype = instr.id

        operands = [self.cmd[i] for i in range(6)]
        for o in operands:
            o.type = o_void
        instr.parseOperands(operands, op, self.cmd)

        return self.cmd.size

    def emu(self):
        feature = self.cmd.get_canon_feature()
        if feature & CF_JUMP:
            QueueMark(Q_jumps, self.cmd.ea)
        if not feature & CF_STOP:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
        return True

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        else:
            return False
        return True

    def out(self):
        buf = init_output_buffer(1024)
        OutMnem(15)

        instr = self.instrs_list[self.cmd.itype]

        for i in range(6):
            if self.cmd[i].type == o_void:
                break
            if i > 0:
                out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)


def PROCESSOR_ENTRY():
    return MicroBlazeProcessor()
