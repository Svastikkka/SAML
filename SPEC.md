# संस्कृत-यंत्रभाषा (SAML) — Language Specification v0.1

## Overview

SAML (Sanskrit Assembly Language) is a Devanagari-script assembly language
that compiles to x86-64 machine code via ELF64 binaries on Linux.

Source files use UTF-8 encoding with Devanagari script for all mnemonics,
register names, and identifiers. File extension: `.sam`

---

## Comment Syntax

```
॥ यह एक टिप्पणी है  (full-line comment)
नय गणक, १०  ॥ इनलाइन टिप्पणी
```

---

## Registers

| SAML Name | Role Description     | x86-64 | Size |
|-----------|----------------------|--------|------|
| गणक       | accumulator/counter  | rax    | 64   |
| गण्य      | count register       | rcx    | 64   |
| आधार      | base register        | rbx    | 64   |
| संग्रह    | store/data           | rdx    | 64   |
| फलम्      | result/destination   | rdi    | 64   |
| सूची      | index/source         | rsi    | 64   |
| स्मृति    | stack pointer        | rsp    | 64   |
| आधार२     | base pointer         | rbp    | 64   |
| विस्तार१  | extended reg 1       | r8     | 64   |
| विस्तार२  | extended reg 2       | r9     | 64   |
| विस्तार३  | extended reg 3       | r10    | 64   |
| विस्तार४  | extended reg 4       | r11    | 64   |

---

## Instruction Set

### Data Movement
| Mnemonic    | Args            | x86-64 | Description        |
|-------------|-----------------|--------|--------------------|
| नय          | dst, src/imm    | mov    | move/load value    |
| रख          | [mem], src      | mov    | store to memory    |
| ले           | dst, [mem]      | mov    | load from memory   |
| विनिमय      | reg1, reg2      | xchg   | exchange registers |

### Arithmetic
| Mnemonic    | Args         | x86-64 | Description      |
|-------------|--------------|--------|------------------|
| योग         | dst, src/imm | add    | addition         |
| वियोग       | dst, src/imm | sub    | subtraction      |
| गुण         | src/imm      | imul   | multiply (rax)   |
| भाग         | src          | idiv   | divide (rax/rdx) |
| वृद्धि      | reg          | inc    | increment        |
| ह्रास       | reg          | dec    | decrement        |
| नाश         | reg          | neg    | negate           |

### Logic / Bitwise
| Mnemonic    | Args         | x86-64 | Description  |
|-------------|--------------|--------|--------------|
| च           | dst, src/imm | and    | bitwise AND  |
| वा          | dst, src/imm | or     | bitwise OR   |
| न           | dst, src/imm | xor    | bitwise XOR  |
| विलोम       | reg          | not    | bitwise NOT  |
| वाम         | dst, imm     | shl    | shift left   |
| दक्षिण      | dst, imm     | shr    | shift right  |

### Comparison & Jumps
| Mnemonic    | Args   | x86-64 | Description              |
|-------------|--------|--------|--------------------------|
| तुल         | a, b   | cmp    | compare (set flags)      |
| परीक्ष      | a, b   | test   | bitwise test (set flags) |
| गच्छ        | label  | jmp    | unconditional jump       |
| यदि         | label  | je/jz  | jump if equal/zero       |
| यदिन        | label  | jne    | jump if not equal        |
| अधिक        | label  | jg     | jump if greater          |
| न्यून       | label  | jl     | jump if less             |
| अधिकसम     | label  | jge    | jump if greater/equal    |
| न्यूनसम     | label  | jle    | jump if less/equal       |

### Stack
| Mnemonic    | Args  | x86-64 | Description      |
|-------------|-------|--------|------------------|
| धर          | reg   | push   | push to stack    |
| उठ          | reg   | pop    | pop from stack   |

### Functions
| Mnemonic       | Args   | x86-64 | Description       |
|----------------|--------|--------|-------------------|
| आह्वय          | label  | call   | call function     |
| प्रत्यागच्छ    |        | ret    | return            |

### System
| Mnemonic    | Args  | x86-64  | Description       |
|-------------|-------|---------|-------------------|
| व्यवस्था    |       | syscall | Linux syscall     |
| विराम       |       | hlt     | halt              |
| रिक्त       |       | nop     | no operation      |

---

## Sections

```
.पाठ्य        ; .text  — code section
.आँकड़ा       ; .data  — initialized data
.अपाठ्य       ; .bss   — uninitialized data
```

---

## Directives

```
.पूर्णांक   value         ; db (1 byte)
.लघु        value         ; dw (2 bytes)
.माध्यम     value         ; dd (4 bytes)
.दीर्घ      value         ; dq (8 bytes)
.वर्ण       "text", ०    ; string + null terminator
.स्थान      n             ; reserve n bytes (bss)
.वैश्विक    label         ; global symbol export
```

---

## Labels and Immediates

```
मुख्य:           ; label definition
गच्छ मुख्य      ; label reference
नय गणक, ४२     ; immediate integer (Devanagari or ASCII digits)
नय गणक, 0x2A   ; hex immediate
```

---

## Calling Convention (Linux x86-64 System V ABI)

Arguments: फलम् (rdi), सूची (rsi), संग्रह (rdx), गण्य (rcx), विस्तार१ (r8), विस्तार२ (r9)
Return value: गणक (rax)
Callee-saved: आधार (rbx), स्मृति (rsp), आधार२ (rbp), विस्तार५–विस्तार१२ (r12–r15)

---

## Example Program

```
॥ नमस्ते विश्व — Hello World in SAML
.पाठ्य
.वैश्विक _start

_start:
    नय गणक,  १            ॥ syscall: write
    नय फलम्,  १            ॥ fd: stdout
    नय सूची,  संदेश        ॥ buffer pointer
    नय संग्रह, १३          ॥ length
    व्यवस्था

    नय गणक,  ६०           ॥ syscall: exit
    नय फलम्,  ०            ॥ exit code 0
    व्यवस्था

.आँकड़ा
संदेश:
    .वर्ण "नमस्ते!", ०x0A, ०
```
