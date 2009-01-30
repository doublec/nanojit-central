/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*- */
/* vi: set ts=4 sw=4 expandtab: (add to ~/.vimrc: set modeline modelines=5) */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is [Open Source Virtual Machine].
 *
 * The Initial Developer of the Original Code is
 * Adobe System Incorporated.
 * Portions created by the Initial Developer are Copyright (C) 2008
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Adobe AS3 Team
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#ifndef __nanojit_NativeX64__
#define __nanojit_NativeX64__

#ifndef NANOJIT_64BIT
#error "NANOJIT_64BIT must be defined for X64 backend"
#endif

#ifdef PERFM
#include "../vprof/vprof.h"
#define count_instr() _nvprof("x64",1)
#define count_prolog() _nvprof("x64-prolog",1); count_instr();
#define count_imt() _nvprof("x64-imt",1) count_instr()
#else
#define count_instr()
#define count_prolog()
#define count_imt()
#endif

namespace nanojit
{
    const int NJ_LOG2_PAGE_SIZE = 12;       // 4K

#define NJ_MAX_STACK_ENTRY              256
#define NJ_ALIGN_STACK                  16

    enum Register {
        RAX = 0, // 1st int return, # of sse varargs
        RCX = 1, // 4th int arg
        RDX = 2, // 3rd int arg 2nd return
        RBX = 3, // saved
        RSP = 4, // stack ptr
        RBP = 5, // frame ptr, saved, sib reqd
        RSI = 6, // 2nd int arg
        RDI = 7, // 1st int arg
        R8  = 8, // 5th int arg
        R9  = 9, // 6th int arg
        R10 = 10, // scratch
        R11 = 11, // scratch
        R12 = 12, // saved
        R13 = 13, // saved, sib reqd like rbp
        R14 = 14, // saved
        R15 = 15, // saved

        XMM0  = 16, // 1st double arg, return
        XMM1  = 17, // 2nd double arg, return
        XMM2  = 18, // 3rd double arg
        XMM3  = 19, // 4th double arg
        XMM4  = 20, // 5th double arg
        XMM5  = 21, // 6th double arg
        XMM6  = 22, // 7th double arg
        XMM7  = 23, // 8th double arg
        XMM8  = 24, // scratch
        XMM9  = 25, // scratch
        XMM10 = 26, // scratch
        XMM11 = 27, // scratch
        XMM12 = 28, // scratch
        XMM13 = 29, // scratch
        XMM14 = 30, // scratch
        XMM15 = 31, // scratch

        FP = RBP,
        UnknownReg = 32,
        FirstReg = RAX,
        LastReg = XMM15,
    };

    enum X64Opcode
#if defined(_MSC_VER) && _MSC_VER >= 1400
#pragma warning(disable:4480) // nonstandard extension used: specifying underlying type for enum
          : uint64_t
#endif
    {
        // 64bit opcode constants
        //              msb        lsb len
        X64_addsp8  = 0x00C4834800000004LL, // 64bit add rsp += imm8
        X64_addqrr  = 0xC003480000000003LL, // 64bit add r += b
        X64_addrr   = 0xC003400000000003LL, // 32bit add r += b
        X64_andqrr  = 0xC023480000000003LL, // 64bit and r &= b
        X64_andrr   = 0xC023400000000003LL, // 32bit and r &= b
        X64_call    = 0x00000000E8000005LL, // near call
        X64_callrax = 0xD0FF000000000002LL, // indirect call to addr in rax (no REX)
        X64_cmovqne = 0xC0450F4800000004LL, // 64bit conditional mov if (c) r = b
        X64_cmplr   = 0xC03B400000000003LL, // 32bit compare r,b
        X64_cmpqr   = 0xC03B480000000003LL, // 64bit compare r,b
        X64_cvtsi2sd= 0xC02A0F40F2000005LL, // convert int32 to double r = (double) b
        X64_cvtsq2sd= 0xC02A0F48F2000005LL, // convert int64 to double r = (double) b
        X64_divsd   = 0xC05E0F40F2000005LL, // divide scalar double r /= b
        X64_mulsd   = 0xC0590F40F2000005LL, // multiply scalar double r *= b
        X64_addsd   = 0xC0580F40F2000005LL, // add scalar double r += b
        X64_imul    = 0xC0AF0F4000000004LL, // 32bit signed mul edx:eax = eax * b
        X64_jmp     = 0x00000000E9000005LL, // jump near
        X64_jb      = 0x00000000820F0006LL, // jump near if below (uint <)
        X64_jae     = 0x00000000830F0006LL, // jump near if above or equal (uint >=)
        X64_ja      = 0x00000000870F0006LL, // jump near if above (uint >)
        X64_jbe     = 0x00000000860F0006LL, // jump near if below or equal (uint <=)
        X64_je      = 0x00000000840F0006LL, // near jump if equal
        X64_jne     = 0x00000000850F0006LL, // jump near if not equal
        X64_jl      = 0x000000008C0F0006LL, // jump near if less (int <)
        X64_jge     = 0x000000008D0F0006LL, // jump near if greater or equal (int >=)
        X64_jg      = 0x000000008F0F0006LL, // jump near if greater (int >)
        X64_jle     = 0x000000008E0F0006LL, // jump near if less or equal (int <=)
        X64_jp      = 0x000000008A0F0006LL, // jump near if parity (PF == 1)
        X64_jnp     = 0x000000008B0F0006LL, // jump near if not parity (PF == 0)
        X64_jp8     = 0x007A000000000002LL, // jump near if parity (PF == 1) 8bit offset
        X64_leaqrm  = 0x00000000808D4807LL, // 64bit load effective addr reg <- disp32+base
        X64_learm   = 0x00000000808D4007LL, // 32bit load effective addr reg <- disp32+base
        X64_movlr   = 0xC08B400000000003LL, // 32bit mov r <- b
        X64_movlmr  = 0x0000000080894007LL, // 32bit store r -> [b+d32]
        X64_movlrm  = 0x00000000808B4007LL, // 32bit load r <- [b+d32]
        X64_movrd   = 0x0000000000B84007LL, // 32bit mov r <- i32
        X64_movqmr  = 0x0000000080894807LL, // 64bit store gpr -> [b+d32]
        X64_movqr   = 0xC08B480000000003LL, // 64bit mov r <- b
        X64_movqi   = 0xB848000000000002LL, // 64bit mov r <- imm64
        X64_movi    = 0xB840000000000002LL, // 32bit mov r <- imm32
        X64_movqrx  = 0xC07E0F4866000005LL, // 64bit mov b <- xmm-r
        X64_movqxr  = 0xC06E0F4866000005LL, // 64bit mov b -> xmm-r
        X64_movqrm  = 0x00000000808B4807LL, // 64bit load r <- [b+d32]
        X64_movsdrr = 0xC0100F40F2000005LL, // 64bit mov xmm-r <- xmm-b
        X64_movsdrm = 0x80100F40F2000005LL, // 64bit load xmm-r <- [b+d32]
        X64_movsdmr = 0x80110F40F2000005LL, // 64bit store xmm-r -> [b+d32]
        X64_movsxdr = 0xC063480000000003LL, // sign extend i32 to i64 r = (int64)(int32) b
        X64_movzx8  = 0xC0B60F4000000004LL, // zero extend i8 to i64 r = (uint64)(uint8) b
        X64_neg     = 0xD8F7400000000003LL, // 32bit two's compliment b = -b
        X64_nop1    = 0x9000000000000001LL, // one byte NOP
        X64_nop2    = 0x9066000000000002LL, // two byte NOP
        X64_nop3    = 0x001F0F0000000003LL, // three byte NOP
        X64_nop4    = 0x00401F0F00000004LL, // four byte NOP
        X64_nop5    = 0x0000441F0F000005LL, // five byte NOP
        X64_nop6    = 0x0000441F0F660006LL, // six byte NOP
        X64_nop7    = 0x00000000801F0F07LL, // seven byte NOP
        X64_not     = 0xD0F7400000000003LL, // 32bit ones compliment b = ~b
        X64_orlrr   = 0xC00B400000000003LL, // 32bit or r |= b
        X64_orqrr   = 0xC00B480000000003LL, // 64bit or r |= b
        X64_pop     = 0x5800000000000001LL, // pop stack (no REX)
        X64_pushr   = 0x5040000000000002LL, // 64bit push r
        X64_pxor    = 0xC0EF0F4066000005LL, // 128bit xor xmm-r ^= xmm-b
        X64_ret     = 0xC300000000000001LL, // near return from called procedure
        X64_sete    = 0xC0940F4000000004LL, // set byte if equal (ZF == 1)
        X64_seto    = 0xC0900F4000000004LL, // set byte if overflow (OF == 1)
        X64_setc    = 0xC0920F4000000004LL, // set byte if carry (CF == 1)
        X64_setl    = 0xC09C0F4000000004LL, // set byte if less (int <) (SF != OF)
        X64_setle   = 0xC09E0F4000000004LL, // set byte if less or equal (int <=) (ZF == 1 || SF != OF)
        X64_setg    = 0xC09F0F4000000004LL, // set byte if greater (int >) (ZF == 0 && SF == OF)
        X64_setge   = 0xC09D0F4000000004LL, // set byte if greater or equal (int >=) (SF == OF)
        X64_seta    = 0xC0970F4000000004LL, // set byte if above (uint >) (CF == 0 && ZF == 0)
        X64_setae   = 0xC0930F4000000004LL, // set byte if above or equal (uint >=) (CF == 0)
        X64_setb    = 0xC0920F4000000004LL, // set byte if below (uint <) (CF == 1)
        X64_setbe   = 0xC0960F4000000004LL, // set byte if below or equal (uint <=) (ZF == 1 || CF == 1)
        X64_subsd   = 0xC05C0F40F2000005LL, // subtract scalar double r -= b
        X64_shl     = 0xE0D3400000000003LL, // 32bit left shift r <<= rcx
        X64_shlq    = 0xE0D3480000000003LL, // 64bit left shift r <<= rcx
        X64_shr     = 0xE8D3400000000003LL, // 32bit uint right shift r >>= rcx
        X64_shrq    = 0xE8D3480000000003LL, // 64bit uint right shift r >>= rcx
        X64_sar     = 0xF8D3400000000003LL, // 32bit int right shift r >>= rcx
        X64_sarq    = 0xF8D3480000000003LL, // 64bit int right shift r >>= rcx
        X64_subqrr  = 0xC02B480000000003LL, // 64bit sub r -= b
        X64_subrr   = 0xC02B400000000003LL, // 32bit sub r -= b
        X64_subspi  = 0x00000000EC814807LL, // 64bit sub rsp -= imm32
        X64_ucomisd = 0xC02E0F4066000005LL, // unordered compare scalar double
        X64_xorqrr  = 0xC033480000000003LL, // 64bit xor r &= b
        X64_xorrr   = 0xC033400000000003LL, // 32bit xor r &= b

        X86_and8r   = 0xC022000000000002LL, // and rl,rh
        X86_sete    = 0xC0940F0000000003LL, // no-rex version of X64_sete
        X86_setnp   = 0xC09B0F0000000003LL, // no-rex set byte if odd parity (ordered fcmp result) (PF == 0)
    };

    typedef uint32_t RegisterMask;

    static const RegisterMask GpRegs = 0xffff;
    static const RegisterMask FpRegs = 0xffff0000;
    static const RegisterMask SavedRegs = 1<<RBX | 1<<R12 | 1<<R13 | 1<<R14 | 1<<R15;
    static const int NumSavedRegs = 5; // rbx, r12-15

    static inline bool IsFpReg(Register r) {
        return (1<<r) & FpRegs;
    }
    static inline bool IsGpReg(Register r) {
        return (1<<r) & GpRegs;
    }

    verbose_only( extern const char* regNames[]; )

    #define DECLARE_PLATFORM_STATS()
    #define DECLARE_PLATFORM_REGALLOC()

    #define DECLARE_PLATFORM_ASSEMBLER()                                    \
        const static Register argRegs[6], retRegs[2];                       \
        void underrunProtect(ptrdiff_t bytes);                              \
        void nativePageReset();                                             \
        void nativePageSetup();                                             \
        void asm_qbinop(LIns*);                                             \
        void MR(Register, Register);\
        void JMP(NIns*);\
        void emit(uint64_t op);\
        void emit8(uint64_t op, int val);\
        void emit32(uint64_t op, int64_t val);\
        void emitr(uint64_t op, Register r);\
        void emitr1(uint64_t op, Register b);\
        void emitrr(uint64_t op, Register r, Register b);\
        void emitprr(uint64_t op, Register r, Register b);\
        void emitrm(uint64_t op, Register r, int32_t d, Register b);\
        void emitprm32(uint64_t op, Register r, int32_t d, Register b);\
        void emit_int(Register r, int32_t v);\
        void emit_quad(Register r, uint64_t v);\
        void asm_regarg(ArgSize, LIns*, Register);\
        void asm_stkarg(ArgSize, LIns*);\
        void asm_shift(LIns*);\
        void regalloc_unary(LIns *ins, RegisterMask allow, Register &rr, Register &ra);\
        void regalloc_binary(LIns *ins, RegisterMask allow, Register &rr, Register &ra, Register &rb);\
        void regalloc_load(LIns *ins, Register &rr, int32_t &d, Register &rb);\
        void dis(NIns *p, int bytes);\
        void asm_cmp(LIns*);\
        void fcmp(LIns*, LIns*);\
        NIns* asm_fbranch(bool, LIns*, NIns*);

	#define swapptrs()  { NIns* _tins = _nIns; _nIns=_nExitIns; _nExitIns=_tins; }

    const int LARGEST_UNDERRUN_PROT = 32;  // largest value passed to underrunProtect

    typedef uint8_t NIns;

    inline Register nextreg(Register r) {
        return Register(r+1);
    }

} // namespace nanojit

#endif // __nanojit_NativeX64__
