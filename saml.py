#!/usr/bin/env python3
"""
संस्कृत-यंत्रभाषा (SAML) — Stage 0 Bootstrap Assembler
Sanskrit Assembly Language → x86-64 ELF64 binary

Usage:
    python3 saml.py input.sam -o output
    python3 saml.py input.sam          (outputs a.out)
"""

import sys
import struct
import re
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────
# REGISTER TABLE  (Sanskrit name → REG number)
# ─────────────────────────────────────────────────────────────
REGISTERS = {
    # 64-bit general purpose
    "गणक":      0,   # rax — accumulator
    "गण्य":     1,   # rcx — count
    "संग्रह":   2,   # rdx — store/data
    "आधार":     3,   # rbx — base
    "स्मृति":   4,   # rsp — stack pointer
    "आधार२":    5,   # rbp — base pointer
    "सूची":     6,   # rsi — index/source
    "फलम्":     7,   # rdi — result/dest
    "विस्तार१": 8,   # r8
    "विस्तार२": 9,   # r9
    "विस्तार३": 10,  # r10
    "विस्तार४": 11,  # r11
    "विस्तार५": 12,  # r12
    "विस्तार६": 13,  # r13
    "विस्तार७": 14,  # r14
    "विस्तार८": 15,  # r15
}

# Reverse map for display
REG_NAMES = {v: k for k, v in REGISTERS.items()}

# ─────────────────────────────────────────────────────────────
# SECTIONS / DIRECTIVES
# ─────────────────────────────────────────────────────────────
SECTIONS = {
    ".पाठ्य":  ".text",
    ".आँकड़ा": ".data",
    ".अपाठ्य": ".bss",
}

DATA_DIRECTIVES = {
    ".पूर्णांक": 1,   # db  — 1 byte
    ".लघु":      2,   # dw  — 2 bytes
    ".माध्यम":   4,   # dd  — 4 bytes
    ".दीर्घ":    8,   # dq  — 8 bytes
}

# ─────────────────────────────────────────────────────────────
# DEVANAGARI DIGIT → ASCII DIGIT
# ─────────────────────────────────────────────────────────────
DEVA_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

def parse_int(s: str) -> int:
    """Parse Devanagari or ASCII integer literals including hex."""
    s = s.translate(DEVA_DIGITS).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)

# ─────────────────────────────────────────────────────────────
# TOKEN
# ─────────────────────────────────────────────────────────────
@dataclass
class Token:
    kind: str   # MNEMONIC | REG | IMM | LABEL_DEF | LABEL_REF | DIRECTIVE | STRING | NEWLINE
    value: str
    line: int

# ─────────────────────────────────────────────────────────────
# LEXER
# ─────────────────────────────────────────────────────────────
class Lexer:
    COMMENT_RE = re.compile(r"॥.*")
    LABEL_DEF_RE = re.compile(r"^([^\s:,\[\]]+):$")

    def __init__(self, source: str):
        self.tokens: list[Token] = []
        self._tokenize(source)

    def _tokenize(self, source: str):
        for lineno, raw_line in enumerate(source.splitlines(), 1):
            line = self.COMMENT_RE.sub("", raw_line).strip()
            if not line:
                continue

            # Check for section directive (starts with .)
            if line in SECTIONS:
                self.tokens.append(Token("SECTION", SECTIONS[line], lineno))
                continue

            # Check for label definition  e.g.  मुख्य:
            if line.endswith(":") and " " not in line:
                label = line[:-1]
                self.tokens.append(Token("LABEL_DEF", label, lineno))
                continue

            # Split into parts (handle commas as delimiters)
            parts = [p.strip() for p in re.split(r"[,\s]+", line) if p.strip()]
            if not parts:
                continue

            mnemonic = parts[0]
            self.tokens.append(Token("MNEMONIC", mnemonic, lineno))

            for part in parts[1:]:
                # Memory reference  [reg] or [label]
                if part.startswith("[") and part.endswith("]"):
                    inner = part[1:-1].strip()
                    self.tokens.append(Token("MEM", inner, lineno))
                # String literal
                elif part.startswith('"'):
                    self.tokens.append(Token("STRING", part, lineno))
                # Register
                elif part in REGISTERS:
                    self.tokens.append(Token("REG", part, lineno))
                # Immediate (Devanagari digits, ASCII digits, or hex)
                elif re.match(r"^[0-9०-९]|^0[xX]", part):
                    self.tokens.append(Token("IMM", part, lineno))
                # Label reference
                else:
                    self.tokens.append(Token("LABEL_REF", part, lineno))

# ─────────────────────────────────────────────────────────────
# x86-64 ENCODER
# Emits raw bytes for each instruction.
# ─────────────────────────────────────────────────────────────
def rex(w=1, r=0, x=0, b=0) -> int:
    """Build REX prefix byte."""
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b

def modrm(mod, reg, rm) -> int:
    return ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)

def encode_reg_reg(opcode: int, dst: int, src: int) -> bytes:
    """REX.W + opcode + ModRM for reg/reg ops.
    For r64,r/m64 form: reg field = dst, rm field = src."""
    r_bit = (dst >> 3) & 1
    b_bit = (src >> 3) & 1
    return bytes([rex(w=1, r=r_bit, b=b_bit), opcode,
                  modrm(3, dst & 7, src & 7)])

def encode_reg_imm(opcode_ext: int, reg: int, imm: int, imm_bytes=4) -> bytes:
    """REX.W + 0x81 (or 0x83) + ModRM + imm for reg/imm ops."""
    b_bit = (reg >> 3) & 1
    if -128 <= imm <= 127 and imm_bytes <= 4:
        # sign-extended 8-bit immediate (opcode 0x83)
        return bytes([rex(w=1, b=b_bit), 0x83,
                      modrm(3, opcode_ext, reg & 7),
                      imm & 0xFF])
    else:
        imm_enc = struct.pack("<i", imm)
        return bytes([rex(w=1, b=b_bit), 0x81,
                      modrm(3, opcode_ext, reg & 7)]) + imm_enc

def encode_mov_reg_imm(reg: int, imm: int) -> bytes:
    """MOV reg, imm64 — REX.W B8+rd id."""
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xB8 | (reg & 7)]) + struct.pack("<q", imm)

def encode_mov_reg_reg(dst: int, src: int) -> bytes:
    """MOV dst, src  (reg/reg).
    Opcode 0x89: MOV r/m64,r64 — src in reg field, dst in rm field."""
    r_bit = (src >> 3) & 1
    b_bit = (dst >> 3) & 1
    return bytes([rex(w=1, r=r_bit, b=b_bit), 0x89,
                  modrm(3, src & 7, dst & 7)])

def encode_push(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    if b_bit:
        return bytes([rex(w=0, b=1), 0x50 | (reg & 7)])
    return bytes([0x50 | (reg & 7)])

def encode_pop(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    if b_bit:
        return bytes([rex(w=0, b=1), 0x58 | (reg & 7)])
    return bytes([0x58 | (reg & 7)])

def encode_jmp_rel32(offset: int) -> bytes:
    return b"\xE9" + struct.pack("<i", offset)

def encode_je_rel32(offset: int) -> bytes:
    return b"\x0F\x84" + struct.pack("<i", offset)

def encode_jne_rel32(offset: int) -> bytes:
    return b"\x0F\x85" + struct.pack("<i", offset)

def encode_jg_rel32(offset: int) -> bytes:
    return b"\x0F\x8F" + struct.pack("<i", offset)

def encode_jl_rel32(offset: int) -> bytes:
    return b"\x0F\x8C" + struct.pack("<i", offset)

def encode_jge_rel32(offset: int) -> bytes:
    return b"\x0F\x8D" + struct.pack("<i", offset)

def encode_jle_rel32(offset: int) -> bytes:
    return b"\x0F\x8E" + struct.pack("<i", offset)

def encode_call_rel32(offset: int) -> bytes:
    return b"\xE8" + struct.pack("<i", offset)

def encode_cmp_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(7, reg, imm)

def encode_cmp_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x3B, dst, src)

def encode_test_reg_reg(a: int, b: int) -> bytes:
    return encode_reg_reg(0x85, a, b)

def encode_add_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(0, reg, imm)

def encode_add_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x03, dst, src)

def encode_sub_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(5, reg, imm)

def encode_sub_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x2B, dst, src)

def encode_and_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(4, reg, imm)

def encode_and_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x23, dst, src)

def encode_or_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(1, reg, imm)

def encode_or_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x0B, dst, src)

def encode_xor_reg_imm(reg: int, imm: int) -> bytes:
    return encode_reg_imm(6, reg, imm)

def encode_xor_reg_reg(dst: int, src: int) -> bytes:
    return encode_reg_reg(0x33, dst, src)

def encode_inc(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xFF, modrm(3, 0, reg & 7)])

def encode_dec(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xFF, modrm(3, 1, reg & 7)])

def encode_neg(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xF7, modrm(3, 3, reg & 7)])

def encode_not(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xF7, modrm(3, 2, reg & 7)])

def encode_imul_reg(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xF7, modrm(3, 5, reg & 7)])

def encode_idiv_reg(reg: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xF7, modrm(3, 7, reg & 7)])

def encode_shl(reg: int, imm: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xC1, modrm(3, 4, reg & 7), imm & 0xFF])

def encode_shr(reg: int, imm: int) -> bytes:
    b_bit = (reg >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0xC1, modrm(3, 5, reg & 7), imm & 0xFF])

def encode_xchg(r1: int, r2: int) -> bytes:
    return encode_reg_reg(0x87, r1, r2)

def encode_mov_reg_mem(dst: int, mem_disp: int) -> bytes:
    """MOV dst, [rip+disp32] — RIP-relative load."""
    b_bit = (dst >> 3) & 1
    return bytes([rex(w=1, b=b_bit), 0x8B,
                  modrm(0, dst & 7, 5)]) + struct.pack("<i", mem_disp)

def encode_mov_mem_reg(src: int, mem_disp: int) -> bytes:
    """MOV [rip+disp32], src — RIP-relative store."""
    r_bit = (src >> 3) & 1
    return bytes([rex(w=1, r=r_bit), 0x89,
                  modrm(0, src & 7, 5)]) + struct.pack("<i", mem_disp)

SYSCALL_BYTES = b"\x0F\x05"
RET_BYTES = b"\xC3"
NOP_BYTES = b"\x90"
HLT_BYTES = b"\xF4"

# ─────────────────────────────────────────────────────────────
# ASSEMBLER (2-pass)
# ─────────────────────────────────────────────────────────────
@dataclass
class Fixup:
    """A label reference that needs patching after pass 1."""
    offset: int        # byte offset in code where the 4-byte value lives
    label: str
    instr_end: int     # byte offset right after this instruction (for RIP calc)
    kind: str          # "rel32_jmp" | "rel32_call" | "abs64_mov"

@dataclass
class DataItem:
    data: bytes
    label: Optional[str] = None

class Assembler:
    TEXT_BASE = 0x400000    # standard Linux x86-64 text base
    DATA_BASE  = 0x600000   # data segment base (simplified flat layout)
    PAGE       = 0x200000   # segment padding

    def __init__(self):
        self.code: bytearray = bytearray()
        self.data_section: bytearray = bytearray()
        self.labels: dict[str, int] = {}          # label → virtual address
        self.data_labels: dict[str, int] = {}     # data label → VA
        self.fixups: list[Fixup] = []
        self.global_labels: set[str] = set()
        self.current_section = ".text"
        self.errors: list[str] = []

    def _error(self, msg: str, line: int = 0):
        self.errors.append(f"Line {line}: {msg}")

    def _current_va(self) -> int:
        return self.TEXT_BASE + len(self.code)

    def _data_va(self) -> int:
        return self.DATA_BASE + len(self.data_section)

    # ── Parse a string literal with escape sequences ──────────
    def _parse_string(self, tok_value: str) -> bytes:
        """Parse  "text", 0x0A, 0  style string with byte literals."""
        result = bytearray()
        # strip outer quotes for the main string part
        m = re.match(r'"(.*?)"(.*)', tok_value)
        if m:
            inner = m.group(1)
            # Handle Python-style escapes inside the string
            inner = inner.replace("\\n", "\n").replace("\\0", "\0")
            result.extend(inner.encode("utf-8"))
        return bytes(result)

    # ── Assemble one instruction ───────────────────────────────
    def _assemble_instr(self, tokens: list[Token]):
        mn = tokens[0].value
        line = tokens[0].line
        args = tokens[1:]

        def reg(i):
            if i >= len(args) or args[i].kind != "REG":
                self._error(f"{mn}: expected register arg {i+1}", line)
                return 0
            return REGISTERS[args[i].value]

        def imm(i):
            if i >= len(args) or args[i].kind != "IMM":
                self._error(f"{mn}: expected immediate arg {i+1}", line)
                return 0
            return parse_int(args[i].value)

        def label_ref(i):
            if i >= len(args) or args[i].kind not in ("LABEL_REF",):
                self._error(f"{mn}: expected label arg {i+1}", line)
                return None
            return args[i].value

        def arg_kind(i):
            return args[i].kind if i < len(args) else None

        # ── नय  (mov) ─────────────────────────────────────────
        if mn == "नय":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_mov_reg_reg(dst, REGISTERS[args[1].value]))
            elif arg_kind(1) == "IMM":
                self.code.extend(encode_mov_reg_imm(dst, imm(1)))
            elif arg_kind(1) in ("LABEL_REF",):
                lbl = args[1].value
                off = len(self.code)
                self.code.extend(encode_mov_reg_imm(dst, 0))  # placeholder
                self.fixups.append(Fixup(off + 2, lbl, len(self.code), "abs64_mov"))
            else:
                self._error(f"नय: unsupported operand combination", line)

        # ── ले  (load from memory [label]) ────────────────────
        elif mn == "ले":
            dst = reg(0)
            if arg_kind(1) == "MEM":
                lbl = args[1].value
                off = len(self.code)
                size = 7  # REX + opcode + ModRM + disp32
                self.code.extend(bytes(size))
                self.fixups.append(Fixup(off + 3, lbl, off + size, "rel32_mem_load"))
                # patch opcode bytes now
                dummy = encode_mov_reg_mem(dst, 0)
                self.code[off:off+len(dummy)] = dummy
            else:
                self._error("ले: expected [label]", line)

        # ── रख  (store to memory) ─────────────────────────────
        elif mn == "रख":
            if arg_kind(0) == "MEM" and arg_kind(1) == "REG":
                lbl = args[0].value
                src = REGISTERS[args[1].value]
                off = len(self.code)
                size = 7
                self.code.extend(bytes(size))
                self.fixups.append(Fixup(off + 3, lbl, off + size, "rel32_mem_store"))
                dummy = encode_mov_mem_reg(src, 0)
                self.code[off:off+len(dummy)] = dummy

        # ── योग  (add) ────────────────────────────────────────
        elif mn == "योग":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_add_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_add_reg_imm(dst, imm(1)))

        # ── वियोग  (sub) ──────────────────────────────────────
        elif mn == "वियोग":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_sub_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_sub_reg_imm(dst, imm(1)))

        # ── गुण  (imul) ───────────────────────────────────────
        elif mn == "गुण":
            self.code.extend(encode_imul_reg(reg(0)))

        # ── भाग  (idiv) ───────────────────────────────────────
        elif mn == "भाग":
            self.code.extend(encode_idiv_reg(reg(0)))

        # ── वृद्धि  (inc) ──────────────────────────────────────
        elif mn == "वृद्धि":
            self.code.extend(encode_inc(reg(0)))

        # ── ह्रास  (dec) ──────────────────────────────────────
        elif mn == "ह्रास":
            self.code.extend(encode_dec(reg(0)))

        # ── नाश  (neg) ────────────────────────────────────────
        elif mn == "नाश":
            self.code.extend(encode_neg(reg(0)))

        # ── च  (and) ──────────────────────────────────────────
        elif mn == "च":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_and_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_and_reg_imm(dst, imm(1)))

        # ── वा  (or) ──────────────────────────────────────────
        elif mn == "वा":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_or_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_or_reg_imm(dst, imm(1)))

        # ── न  (xor) ──────────────────────────────────────────
        elif mn == "न":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_xor_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_xor_reg_imm(dst, imm(1)))

        # ── विलोम  (not) ──────────────────────────────────────
        elif mn == "विलोम":
            self.code.extend(encode_not(reg(0)))

        # ── वाम  (shl) ────────────────────────────────────────
        elif mn == "वाम":
            self.code.extend(encode_shl(reg(0), imm(1)))

        # ── दक्षिण  (shr) ─────────────────────────────────────
        elif mn == "दक्षिण":
            self.code.extend(encode_shr(reg(0), imm(1)))

        # ── विनिमय  (xchg) ────────────────────────────────────
        elif mn == "विनिमय":
            self.code.extend(encode_xchg(reg(0), reg(1)))

        # ── तुल  (cmp) ────────────────────────────────────────
        elif mn == "तुल":
            dst = reg(0)
            if arg_kind(1) == "REG":
                self.code.extend(encode_cmp_reg_reg(dst, REGISTERS[args[1].value]))
            else:
                self.code.extend(encode_cmp_reg_imm(dst, imm(1)))

        # ── परीक्ष  (test) ────────────────────────────────────
        elif mn == "परीक्ष":
            self.code.extend(encode_test_reg_reg(reg(0), reg(1)))

        # ── धर  (push) ────────────────────────────────────────
        elif mn == "धर":
            self.code.extend(encode_push(reg(0)))

        # ── उठ  (pop) ─────────────────────────────────────────
        elif mn == "उठ":
            self.code.extend(encode_pop(reg(0)))

        # ── गच्छ  (jmp) ───────────────────────────────────────
        elif mn == "गच्छ":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\xE9\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 1, lbl, len(self.code), "rel32_jmp"))

        # ── यदि  (je) ─────────────────────────────────────────
        elif mn == "यदि":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x84\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── यदिन  (jne) ───────────────────────────────────────
        elif mn == "यदिन":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x85\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── अधिक  (jg) ────────────────────────────────────────
        elif mn == "अधिक":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x8F\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── न्यून  (jl) ───────────────────────────────────────
        elif mn == "न्यून":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x8C\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── अधिकसम  (jge) ────────────────────────────────────
        elif mn == "अधिकसम":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x8D\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── न्यूनसम  (jle) ────────────────────────────────────
        elif mn == "न्यूनसम":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\x0F\x8E\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 2, lbl, len(self.code), "rel32_jmp"))

        # ── आह्वय  (call) ─────────────────────────────────────
        elif mn == "आह्वय":
            lbl = label_ref(0)
            off = len(self.code)
            self.code.extend(b"\xE8\x00\x00\x00\x00")
            self.fixups.append(Fixup(off + 1, lbl, len(self.code), "rel32_jmp"))

        # ── प्रत्यागच्छ  (ret) ────────────────────────────────
        elif mn == "प्रत्यागच्छ":
            self.code.extend(RET_BYTES)

        # ── व्यवस्था  (syscall) ───────────────────────────────
        elif mn == "व्यवस्था":
            self.code.extend(SYSCALL_BYTES)

        # ── विराम  (hlt) ──────────────────────────────────────
        elif mn == "विराम":
            self.code.extend(HLT_BYTES)

        # ── रिक्त  (nop) ──────────────────────────────────────
        elif mn == "रिक्त":
            self.code.extend(NOP_BYTES)

        else:
            self._error(f"Unknown mnemonic: {mn}", line)

    # ── Process data directive ─────────────────────────────────
    def _process_data(self, tokens: list[Token]):
        directive = tokens[0].value
        args = tokens[1:]

        if directive == ".वैश्विक":
            if args:
                self.global_labels.add(args[0].value)
            return

        if directive == ".वर्ण":
            # .वर्ण "text", 0x0A, 0
            result = bytearray()
            for a in args:
                if a.kind == "STRING":
                    result.extend(self._parse_string(a.value))
                elif a.kind == "IMM":
                    result.append(parse_int(a.value) & 0xFF)
            if self.current_section == ".data":
                self.data_section.extend(result)
            else:
                self.code.extend(result)
            return

        if directive in DATA_DIRECTIVES:
            size = DATA_DIRECTIVES[directive]
            if args:
                val = parse_int(args[0].value) if args[0].kind == "IMM" else 0
                packed = struct.pack({1:"<B",2:"<H",4:"<I",8:"<Q"}[size], val & ((1<<(size*8))-1))
                if self.current_section == ".data":
                    self.data_section.extend(packed)
                else:
                    self.code.extend(packed)
            return

        if directive == ".स्थान":
            # BSS reservation
            if args:
                n = parse_int(args[0].value)
                self.data_section.extend(bytes(n))
            return

    # ── Main assemble pass ────────────────────────────────────
    def assemble(self, tokens: list[Token]):
        # Group tokens into logical lines (up to each MNEMONIC / LABEL_DEF)
        i = 0
        while i < len(tokens):
            tok = tokens[i]

            if tok.kind == "SECTION":
                self.current_section = tok.value
                i += 1
                continue

            if tok.kind == "LABEL_DEF":
                if self.current_section == ".data":
                    self.data_labels[tok.value] = self._data_va()
                else:
                    self.labels[tok.value] = self._current_va()
                i += 1
                continue

            if tok.kind == "MNEMONIC":
                # Collect this instruction's tokens
                line_toks = [tok]
                i += 1
                while i < len(tokens) and tokens[i].kind not in ("MNEMONIC", "LABEL_DEF", "SECTION"):
                    line_toks.append(tokens[i])
                    i += 1

                mn = tok.value
                if mn in (".वैश्विक", ".वर्ण") or mn in DATA_DIRECTIVES or mn == ".स्थान":
                    self._process_data(line_toks)
                else:
                    self._assemble_instr(line_toks)
                continue

            i += 1  # skip unexpected tokens

        # ── Apply fixups ──────────────────────────────────────
        all_labels = {**self.labels, **self.data_labels}
        for fixup in self.fixups:
            if fixup.label not in all_labels:
                self.errors.append(f"Undefined label: {fixup.label}")
                continue
            target_va = all_labels[fixup.label]

            if fixup.kind == "rel32_jmp":
                # relative to end of instruction
                current_va = self.TEXT_BASE + fixup.instr_end
                rel = target_va - current_va
                struct.pack_into("<i", self.code, fixup.offset, rel)

            elif fixup.kind == "abs64_mov":
                # absolute 64-bit value embedded in mov reg, imm64
                struct.pack_into("<q", self.code, fixup.offset, target_va)

            elif fixup.kind in ("rel32_mem_load", "rel32_mem_store"):
                # RIP-relative memory access
                current_va = self.TEXT_BASE + fixup.instr_end
                rel = target_va - current_va
                struct.pack_into("<i", self.code, fixup.offset, rel)

# ─────────────────────────────────────────────────────────────
# ELF64 WRITER
# ─────────────────────────────────────────────────────────────
def write_elf64(code: bytes, data: bytes, entry_va: int, text_base: int,
                data_base: int, data_offset_in_file: int) -> bytes:
    """Build a minimal static ELF64 executable."""

    PAGE = 0x1000
    HDR_SIZE     = 64
    PHDR_SIZE    = 56
    N_PHDRS      = 2
    HEADERS_SIZE = HDR_SIZE + N_PHDRS * PHDR_SIZE

    # The classic static ELF trick: map the entire file (headers + code) at
    # text_base with file offset 0.  That way VA(text_base + HEADERS_SIZE)
    # is where the first byte of code lives, and _start must be set to that.
    TEXT_FILE_OFF = HEADERS_SIZE   # code starts here in the file
    TEXT_VADDR    = text_base      # segment loaded at text_base, file off 0

    # _start VA = text_base + HEADERS_SIZE
    # (The assembler already set labels relative to TEXT_BASE which is
    #  passed in as text_base, so we adjust entry here.)
    adjusted_entry = entry_va + HEADERS_SIZE

    # Data segment: packed after code, page-aligned in both file and VA.
    DATA_FILE_OFF_RAW = TEXT_FILE_OFF + len(code)
    pad = (PAGE - DATA_FILE_OFF_RAW % PAGE) % PAGE
    DATA_FILE_OFF = DATA_FILE_OFF_RAW + pad
    DATA_VADDR    = data_base

    # ELF64 header
    elf_ident = (
        b"\x7fELF"
        + b"\x02"      # ELFCLASS64
        + b"\x01"      # ELFDATA2LSB
        + b"\x01"      # EV_CURRENT
        + b"\x00"      # ELFOSABI_NONE
        + b"\x00" * 8  # padding
    )
    elf_fields = struct.pack(
        "<HHIQQQIHHHHHH",
        2,               # ET_EXEC
        62,              # EM_X86_64
        1,               # EV_CURRENT
        adjusted_entry,  # e_entry  ← adjusted for headers offset
        HDR_SIZE,        # e_phoff
        0,               # e_shoff
        0,               # e_flags
        HDR_SIZE,
        PHDR_SIZE,
        N_PHDRS,
        64,
        0,
        0,
    )
    elf_header = elf_ident + elf_fields

    def phdr(p_type, flags, offset, vaddr, paddr, filesz, memsz, align):
        return struct.pack("<IIQQQQQQ",
                           p_type, flags, offset, vaddr, paddr,
                           filesz, memsz, align)

    PT_LOAD = 1
    PF_X = 1; PF_W = 2; PF_R = 4

    phdr_text = phdr(PT_LOAD, PF_R | PF_X,
                     0,            # file offset 0 — map entire file start
                     TEXT_VADDR,   # vaddr = text_base
                     TEXT_VADDR,
                     TEXT_FILE_OFF + len(code),   # filesz
                     TEXT_FILE_OFF + len(code),   # memsz
                     0x200000)

    phdr_data = phdr(PT_LOAD, PF_R | PF_W,
                     DATA_FILE_OFF, DATA_VADDR, DATA_VADDR,
                     len(data), len(data),
                     PAGE)

    result = bytearray(elf_header + phdr_text + phdr_data)
    # Pad to TEXT_FILE_OFF
    while len(result) < TEXT_FILE_OFF:
        result.append(0)
    result.extend(code)
    # Pad to DATA_FILE_OFF
    while len(result) < DATA_FILE_OFF:
        result.append(0)
    result.extend(data)
    return bytes(result)

# ─────────────────────────────────────────────────────────────
# DRIVER
# ─────────────────────────────────────────────────────────────
def main():
    import argparse, os, stat

    parser = argparse.ArgumentParser(
        description="SAML — Sanskrit Assembly Language compiler → x86-64 ELF64"
    )
    parser.add_argument("input",  help="Source file (.sam)")
    parser.add_argument("-o", "--output", default="a.out", help="Output binary")
    parser.add_argument("--dump", action="store_true", help="Dump hex of code section")
    parser.add_argument("--labels", action="store_true", help="Print label table")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        source = f.read()

    lexer = Lexer(source)
    asm   = Assembler()
    asm.assemble(lexer.tokens)

    if asm.errors:
        for e in asm.errors:
            print(f"[त्रुटि] {e}", file=sys.stderr)
        sys.exit(1)

    entry_label = "_start"
    if entry_label not in asm.labels:
        print(f"[त्रुटि] Entry label '_start' not found. Define _start: in your .sam file.",
              file=sys.stderr)
        sys.exit(1)

    entry_va = asm.labels[entry_label]

    if args.labels:
        print("\n── Labels ──")
        for lbl, va in sorted(asm.labels.items(), key=lambda x: x[1]):
            print(f"  {lbl:30s}  0x{va:016X}")
        for lbl, va in sorted(asm.data_labels.items(), key=lambda x: x[1]):
            print(f"  {lbl:30s}  0x{va:016X}  [data]")

    if args.dump:
        print("\n── Code bytes ──")
        code_bytes = bytes(asm.code)
        for i in range(0, len(code_bytes), 16):
            chunk = code_bytes[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            print(f"  0x{asm.TEXT_BASE+i:08X}:  {hex_part}")

    elf = write_elf64(
        bytes(asm.code),
        bytes(asm.data_section),
        entry_va,
        asm.TEXT_BASE,
        asm.DATA_BASE,
        0,
    )

    with open(args.output, "wb") as f:
        f.write(elf)

    # Make executable
    os.chmod(args.output, os.stat(args.output).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"✓ {args.input} → {args.output}  ({len(asm.code)} bytes code, {len(asm.data_section)} bytes data)")

if __name__ == "__main__":
    main()
