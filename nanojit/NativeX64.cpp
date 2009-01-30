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
 * Portions created by the Initial Developer are Copyright (C) 2009
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

#ifdef _MAC
// for MakeDataExecutable
#include <CoreServices/CoreServices.h>
#endif

#include "nanojit.h"

#if defined AVMPLUS_UNIX || defined AVMPLUS_MAC
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#endif

#if defined FEATURE_NANOJIT && defined NANOJIT_X64

/*
completion
- 64bit branch offsets
- finish cmov/qcmov with other conditions
- validate asm_cond with other conditions

mir parity
- put R12 back in play as a base register
- no-disp addr modes (except RBP/R13)
- disp8 addressing modes
- disp8 branches
- disp64 branch/call
- fold immedate operands
- don't issue REX when not needed
- don't overwrite PageHeader sentinel (maybe read/modify/write?)
- windows abi
- use sub imm8 to align stack before call

someday
- spill gp values to xmm registers?
- prefer xmm registers for copies since gprs are in higher demand?
- asm_qjoin
- asm_qhi
- stack arg int, double, uint
- stack based LIR_param
- asm_adjustBranch
- asm_loop
- nFragExit

*/ 

namespace nanojit
{
    const Register Assembler::retRegs[] = { RAX, RDX, };
    const Register Assembler::argRegs[] = { RDI, RSI, RDX, RCX, R8, R9 };
    const Register Assembler::savedRegs[] = { RBX, R12, R13, R14, R15 };

    const char *regNames[] = {
        "rax",   "rcx", " rdx",   "rbx",   "rsp",   "rbp",   "rsi",   "rdi",
        "r8",    "r9",   "r10",   "r11",   "r12",   "r13",   "r14",   "r15",
        "xmm0",  "xmm1", "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
        "xmm8",  "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
    };

    #define TODO(x) do { printf(#x); NanoAssertMsgf(false, "%s", #x); } while(0)

    // MODRM and restrictions:
    // memory access modes != 11 require SIB if base&7 == 4 (RSP or R12)
    // mode 00 with base&7 == 5 means RIP+disp32 (RBP or R13), use mode 01 disp8=0 instead

    // take R12 out of play as a base register because it requires the SIB byte like ESP
    const RegisterMask BaseRegs = GpRegs & ~rmask(R12);

    static inline int oplen(uint64_t op) {
        return op & 255;
    }

    // op+r form
    static inline uint64_t X64r(uint64_t op, Register r) {
        NanoAssert(r < 8);
        return op | uint64_t(r)<<56;
    }

    static inline uint64_t rexb(Register b) {
        return (b&8)>>3;
    }

    static inline uint64_t rexrb(Register r, Register b) {
        return (r&8)>>1 | (b&8)>>3;
    }

    static inline uint64_t rexrxb(Register r, Register x, Register b) {
        return (r&8)>>1 | (x&8)>>2 | (b&8)>>3;
    }

    // [rex][opcode][mod-rr]
    static inline uint64_t mod_rr(uint64_t op, Register r, Register b) {
        return uint64_t((r&7)<<3 | (b&7))<<56 | rexrb(r, b)<<(64-8*oplen(op));
    }

    // [rex][opcode][mod-rr] with only b specified, r is hardcoded in op
    static inline uint64_t mod_r1(uint64_t op, Register b) {
        return uint64_t(b&7)<<56 | rexb(b)<<(64-8*oplen(op));
    }

    // [prefix][rex][opcode][mod-rr]
    static inline uint64_t mod_prr(uint64_t op, Register r, Register b) {
        return uint64_t((r&7)<<3 | (b&7))<<56 | rexrb(r, b)<<(64-8*oplen(op)+8);
    }

    static inline uint64_t mod_rm32(uint64_t op, Register r, Register b) {
        NanoAssert(r < 16 && b < 16);
        NanoAssert((b & 7) != 4); // using RSP or R12 as base requires SIB
        return uint64_t((r&7)<<3 | (b&7))<<24 | rexrb(r, b)<<(64-8*oplen(op));
    }

    #ifdef NJ_VERBOSE
    void Assembler::dis(NIns *p, int bytes) {
        char b[32], *s = b; // room for 8 hex bytes plus null
        *s++ = ' ';
        for (NIns *end = p + bytes; p < end; p++) {
            sprintf(s, "%02x ", *p);
            s += 3;
        }
        *s = 0;
        asm_output("%s", b);
    }
    #endif

    void Assembler::emit(uint64_t op) {
        int len = oplen(op);
        // we will only move nIns by -len bytes, but we write 8
        // bytes.  so need to protect 8 so we dont stomp the page
        // header or the end of the preceding page (might segf)
        underrunProtect(8);
        ((int64_t*)_nIns)[-1] = op;
        _nIns -= len; // move pointer by length encoded in opcode
        verbose_only( if (_verbose) dis(_nIns, len); )
    }

    void Assembler::emit8(uint64_t op, int v) {
        NanoAssert(isS8(v));
        emit(op | uint64_t(v)<<56);
    }

    void Assembler::emit32(uint64_t op, int64_t v) {
        NanoAssert(isS32(v));
        emit(op | uint64_t(uint32_t(v))<<32);
    }

    // single-register form, no modrm, r is part of opcode
    void Assembler::emitr(uint64_t op, Register r) {
        emit(op | uint64_t(r&7)<<56 | rexb(r)<<(64-8*oplen(op)));
    }

    // 1-register modrm form (r is hardcoded, b is the 1 register)
    void Assembler::emitr1(uint64_t op, Register b) {
        emit(op | mod_r1(op, b));
    }

    // 2-register modrm form
    void Assembler::emitrr(uint64_t op, Register r, Register b) {
        emit(op | mod_rr(op, r, b));
    }

    // same as emitrr, but with a prefix byte
    void Assembler::emitprr(uint64_t op, Register r, Register b) {
        emit(op | mod_prr(op, r, b));
    }

    // disp32 modrm form, when the disp fits in the instruction (opcode is 1-3 bytes)
    void Assembler::emitrm(uint64_t op, Register r, int32_t d, Register b) {
        emit32(op | mod_rm32(op, r, b), d);
    }

    // disp32 modrm form when the disp must be written separately (opcode is 4+ bytes)
    void Assembler::emitprm32(uint64_t op, Register r, int32_t d, Register b) {
        underrunProtect(4+8); // room for displ plus fullsize op
        *((int32_t*)(_nIns -= 4)) = d;
        emitprr(op, r, b);
    }

    void Assembler::MR(Register d, Register s) {
        NanoAssert(IsGpReg(d) && IsGpReg(s));
        emitrr(X64_movqr, d, s);
    }

    void Assembler::JMP(NIns *target) {
        if (!target || isS32(target - _nIns)) {
            underrunProtect(8); // must do this before calculating offset
            emit32(X64_jmp, target ? target - _nIns : 0);
        } else {
            TODO(jmp64);
        }
    }

    // register allocation for 2-address style ops of the form R = R (op) B
    void Assembler::regalloc_binary(LIns *ins, RegisterMask allow, Register &rr, Register &ra, Register &rb) {
        LIns *a = ins->oprnd1();
        LIns *b = ins->oprnd2();
        if (a != b) {
            rb = findRegFor(b, allow);
            allow &= ~rmask(rb);
        }
        rr = prepResultReg(ins, allow);
        Reservation* rA = getresv(a);
        // if this is last use of a in reg, we can re-use result reg
        if (rA == 0 || (ra = rA->reg) == UnknownReg) {
            ra = findSpecificRegFor(a, rr);
        } else {
            // rA already has a register assigned
        }
        if (a == b) {
            rb = ra;
        }
    }

    void Assembler::asm_qbinop(LIns *ins) {
        asm_arith(ins);
    }

    void Assembler::asm_shift(LIns *ins) {
        // shift require rcx for shift count
        LIns *a = ins->oprnd1();
        LIns *b = ins->oprnd2();
        Register rr, ra;
        if (a != b) {
            findSpecificRegFor(b, RCX);
            regalloc_unary(ins, GpRegs & ~rmask(RCX), rr, ra);
        } else {
            // a == b means both must be in RCX
            regalloc_unary(ins, rmask(RCX), rr, ra);
        }
        X64Opcode xop;
        switch (ins->opcode()) {
        default:
            TODO(asm_shift);
        case LIR_qursh:
            xop = X64_shrq;
            break;
        case LIR_qirsh:
            xop = X64_sarq;
            break;
        case LIR_qilsh:
            xop = X64_shlq;
            break;
        case LIR_ush:
            xop = X64_shr;
            break;
        case LIR_rsh:
            xop = X64_sar;
            break;
        case LIR_lsh:
            xop = X64_shl;
            break;
        }
        emitr1(xop, rr);
        if (rr != ra) 
            MR(rr, ra);
    }

    // binary op with integer registers
    void Assembler::asm_arith(LIns *ins) {
        Register rr, ra, rb;
        LOpcode op = ins->opcode();
        if ((op & ~LIR64) >= LIR_lsh && (op & ~LIR64) <= LIR_ush) {
            asm_shift(ins);
            return;
        }
        regalloc_binary(ins, GpRegs, rr, ra, rb);
        X64Opcode xop;
        switch (ins->opcode()) {
        default:
            TODO(asm_arith);
        case LIR_or:
            xop = X64_orlrr;
            break;
        case LIR_sub:
            xop = X64_subrr;
            break;
        case LIR_iaddp:
        case LIR_add:
            xop = X64_addrr;
            break;
        case LIR_and:
            xop = X64_andrr;
            break;
        case LIR_xor:
            xop = X64_xorrr;
            break;
        case LIR_mul:
            xop = X64_imul;
            break;
        case LIR_qxor:
            xop = X64_xorqrr;
            break;
        case LIR_qior:
            xop = X64_orqrr;
            break;
        case LIR_qiand:
            xop = X64_andqrr;
            break;
        case LIR_qiadd:
        case LIR_qaddp:
            xop = X64_addqrr;
            break;
        }
        emitrr(xop, rr, rb);
        if (rr != ra)
            MR(rr,ra);
    }

    // binary op with fp registers
    void Assembler::asm_fop(LIns *ins) {
        Register rr, ra, rb;
        regalloc_binary(ins, FpRegs, rr, ra, rb);
        X64Opcode xop;
        switch (ins->opcode()) {
        default:
            TODO(asm_fop);
        case LIR_fdiv:
            xop = X64_divsd;
            break;
        case LIR_fmul:
            xop = X64_mulsd;
            break;
        case LIR_fadd:
            xop = X64_addsd;
            break;
        case LIR_fsub:
            xop = X64_subsd;
            break;
        }
        emitprr(xop, rr, rb);
        if (rr != ra) {
            asm_nongp_copy(rr, ra);
        }
    }

    void Assembler::asm_neg_not(LIns *ins) {
        Register rr, ra;
        regalloc_unary(ins, GpRegs, rr, ra);
        NanoAssert(IsGpReg(ra));
        X64Opcode xop;
        if (ins->isop(LIR_not)) {
            xop = X64_not;
        } else {
            xop = X64_neg;
        }
        emitr1(xop, rr);
		if (rr != ra) 
			MR(rr, ra); 
    }

    void Assembler::asm_call(LIns *ins) {
        const CallInfo *call = ins->callInfo();
        ArgSize sizes[MAXARGS];
        int argc = call->get_sizes(sizes);
        int max_int_args = 6;

        // figure out how much stack is needed
        int call_argc = argc - (call->isIndirect() ? 1 : 0) - (call->isInterface() ? 1 : 0);
        int iargs = 0;
        for (int i = 0; i < call_argc; i++) {
            if (sizes[call_argc - i - 1] != ARGSIZE_F)
                iargs++;
        }
        int stk_pad = 0;
        if (iargs > max_int_args) {
            int stk_used = (iargs - max_int_args) * sizeof(void*);
            int stk_total = alignUp(stk_used, NJ_ALIGN_STACK);
            stk_pad = stk_total - stk_used;
            emit8(X64_addsp8, stk_total);
        }

        bool indirect;
        if (!(indirect = call->isIndirect())) {
            verbose_only(if (_verbose)
                outputf("        %p:", _nIns);
            )
            NIns *target = (NIns*)call->_address;
            // must do underrunProtect before calculating offset
            underrunProtect(8);
            if (isS32(target - _nIns)) {
                emit32(X64_call, target - _nIns);
            } else {
                // can't reach target from here, load imm64 and do an indirect jump
                emit(X64_callrax);
                emit_quad(RAX, (uint64_t)target);
            }
        } else {
            // Indirect call: we assign the address arg to RAX since it's not
            // used for regular arguments, and is otherwise scratch since it's
            // clobberred by the call.
            asm_regarg(ARGSIZE_P, ins->arg(--argc), RAX);
            emit(X64_callrax);
        }

        int param_size = 0;
        if (call->isInterface()) {
            asm_regarg(ARGSIZE_P, ins->arg(--argc), argRegs[3]);
            param_size += sizeof(void*);
        }

        int int_arg_index = 0;
        Register fr = XMM0;
        for (int i = 0; i < argc; i++) {
            int j = argc - i - 1;
            ArgSize sz = sizes[j];
            LIns* arg = ins->arg(j);
            if (sz & ARGSIZE_MASK_INT) {
                // gp arg
                if (int_arg_index < max_int_args) {
                    asm_regarg(sz, arg, argRegs[int_arg_index]);
                    int_arg_index++;
                } else {
                    asm_stkarg(sz, arg);
                }
            }
            else if (sz == ARGSIZE_F) {
                // double arg
                if (fr < XMM8) {
                    asm_regarg(sz, arg, fr);
                    fr = nextreg(fr);
                } else {
                    // arg goes on stack
                    TODO(stack_double_arg);
                }
            }
            else {
                TODO(argtype_q);
            }
        }

        if (stk_pad != 0)
            emit32(X64_subspi, stk_pad);
    }

    void Assembler::asm_regarg(ArgSize sz, LIns *p, Register r) {
        if (sz == ARGSIZE_I) {
            // sign extend int32 to int64
            emitrr(X64_movsxdr, r, r);
        } else if (sz == ARGSIZE_U) {
            // zero extend with 32bit mov, auto-zeros upper 32bits
            emitrr(X64_movlr, r, r);
        }
        findSpecificRegFor(p, r);
    }

    void Assembler::asm_stkarg(ArgSize sz, LIns *p) {
        if (sz & ARGSIZE_MASK_INT) {
            Register r = findRegFor(p, GpRegs);
            if (sz == ARGSIZE_I) {
                // extend int32 to int64
                TODO(asm_stkarg_int);
            } else if (sz == ARGSIZE_U) {
                // extend uint32 to uint64
                TODO(asm_stkarg_uint);
            }
            emitr(X64_pushr, r);
        } else {
            TODO(asm_stkarg_non_int);
        }
    }

    void Assembler::asm_promote(LIns *ins) {
        Register rr, ra;
        regalloc_unary(ins, GpRegs, rr, ra);
        NanoAssert(IsGpReg(ra));
        if (ins->isop(LIR_u2q)) {
            emitrr(X64_movlr, rr, ra); // 32bit mov zeros the upper 32bits of the target
        } else {
            NanoAssert(ins->isop(LIR_i2q));
            emitrr(X64_movsxdr, rr, ra); // sign extend 32->64
        }
    }

    void Assembler::asm_short(LIns *ins) {
        asm_int(ins);
    }

    // the CVTSI2SD instruction only writes to the low 64bits of the target
    // XMM register, which hinders register renaming and makes dependence
    // chaings longer.  So we precede with PXOR to clear the target register.

    void Assembler::asm_i2f(LIns *ins) {
        Register r = prepResultReg(ins, FpRegs);
        Register b = findRegFor(ins->oprnd1(), GpRegs);
        emitprr(X64_cvtsi2sd, r, b);    // cvtsi2sd xmmr, b  only writes xmm:0:64
        emitprr(X64_pxor, r, r);        // pxor xmmr,xmmr to break dependency chains
    }

    void Assembler::asm_u2f(LIns *ins) {
        Register r = prepResultReg(ins, FpRegs);
        Register b = findRegFor(ins->oprnd1(), GpRegs);
        NanoAssert(!ins->oprnd1()->isQuad());
        // since oprnd1 value is 32bit, its okay to zero-extend the value without worrying about clobbering.
        emitprr(X64_cvtsq2sd, r, b);    // convert int64 to double
        emitprr(X64_pxor, r, r);        // pxor xmmr,xmmr to break dependency chains
        emitrr(X64_movlr, b, b);        // zero extend u32 to int64
    }

    void Assembler::asm_cmov(LIns *ins) {
        LIns* cond = ins->oprnd1();
        NanoAssert(cond->isCmp());
        LIns* values = ins->oprnd2();
        NanoAssert(values->opcode() == LIR_2);
        LIns* iftrue = values->oprnd1();
        LIns* iffalse = values->oprnd2();

        NanoAssert(ins->isop(LIR_qcmov) && iftrue->isQuad() && iffalse->isQuad() ||
                   ins->isop(LIR_cmov) && !iftrue->isQuad() && !iffalse->isQuad());
        
        // this code assumes that neither LD nor MR nor MRcc set any of the condition flags.
        // (This is true on Intel, is it true on all architectures?)
        const Register rr = prepResultReg(ins, GpRegs);
        const Register rf = findRegFor(iffalse, GpRegs & ~rmask(rr));
        X64Opcode xop;
        switch (cond->opcode()) {
            default: TODO(asm_cmov);
            case LIR_qeq:
                xop = X64_cmovqne;
                break;
        }
        emitrr(xop, rr, rf);
        /*const Register rt =*/ findSpecificRegFor(iftrue, rr);
        asm_cmp(cond);
    }

    NIns* Assembler::asm_branch(bool onFalse, LIns *cond, NIns *target) {
        LOpcode condop = cond->opcode();
        if (condop >= LIR_feq && condop <= LIR_fge)
            return asm_fbranch(onFalse, cond, target);
        // emit the branch
        X64Opcode xop = X64_jmp;
        if (onFalse) {
            switch (condop) {
            default: TODO(branch);
            case LIR_eq:
            case LIR_qeq:   xop = X64_jne;  break;
            case LIR_ult:
            case LIR_qult:  xop = X64_jae;  break;
            case LIR_lt:
            case LIR_qlt:   xop = X64_jge;  break;
            case LIR_gt:
            case LIR_qgt:   xop = X64_jle;  break;
            case LIR_ugt:
            case LIR_qugt:  xop = X64_jbe;  break;
            case LIR_le:
            case LIR_qle:   xop = X64_jg;   break;
            case LIR_ule:
            case LIR_qule:  xop = X64_ja;   break;
            case LIR_ge:
            case LIR_qge:   xop = X64_jl;   break;
            case LIR_uge:
            case LIR_quge:  xop = X64_jb;   break;
            }
        } else {
            switch (condop) {
            default: TODO(branch);
            case LIR_eq:
            case LIR_qeq:   xop = X64_je;   break;
            case LIR_lt:
            case LIR_qlt:   xop = X64_jl;   break;
            case LIR_ult:
            case LIR_qult:  xop = X64_jb;   break;
            case LIR_gt:
            case LIR_qgt:   xop = X64_jg;   break;
            case LIR_ugt:
            case LIR_qugt:  xop = X64_ja;   break;
            case LIR_le:
            case LIR_qle:   xop = X64_jle;  break;
            case LIR_ule:
            case LIR_qule:  xop = X64_jbe;  break;
            case LIR_ge:
            case LIR_qge:   xop = X64_jge;   break;
            case LIR_uge:
            case LIR_quge:  xop = X64_jae;   break;
            }
        }
        underrunProtect(8);             // must do this before calculating offset
        emit32(xop, target ? target - _nIns : 0);
        NIns *patch = _nIns;            // addr of instr to patch
        asm_cmp(cond);
        return patch;
    }

    void Assembler::asm_cmp(LIns *cond) {
        LIns *a = cond->oprnd1();
        LIns *b = cond->oprnd2();
        Register ra, rb;
        if (a != b) {
            Reservation *resva, *resvb;
            findRegFor2(GpRegs, a, resva, b, resvb);
            ra = resva->reg;
            rb = resvb->reg;
        } else {
            // optimize-me: this will produce a const result!
            ra = rb = findRegFor(a, GpRegs);
        }

        LOpcode condop = cond->opcode();
        emitrr(condop & LIR64 ? X64_cmpqr : X64_cmplr, ra, rb);
    }

    // compiling floating point branches
    // discussion in https://bugzilla.mozilla.org/show_bug.cgi?id=443886
    //
    //  fucom/p/pp: c3 c2 c0   jae ja    jbe jb je jne
    //  ucomisd:     Z  P  C   !C  !C&!Z C|Z C  Z  !Z 
    //              -- -- --   --  ----- --- -- -- -- 
    //  unordered    1  1  1             T   T  T     
    //  greater >    0  0  0   T   T               T  
    //  less    <    0  0  1             T   T     T  
    //  equal   =    1  0  0   T         T      T     
    //
    //  here's the cases, using conditionals:
    //
    //  branch  >=  >   <=       <        =
    //  ------  --- --- ---      ---      ---
    //  jt      jae ja  swap+jae swap+ja  jp over je
    //  jf      jb  jbe swap+jb  swap+jbe jne+jp          

    NIns* Assembler::asm_fbranch(bool onFalse, LIns *cond, NIns *target) {
        LOpcode condop = cond->opcode();
        NIns *patch;
        LIns *a = cond->oprnd1();
        LIns *b = cond->oprnd2();
        if (condop == LIR_feq) {
            if (onFalse) {
                // branch if unordered or !=
                underrunProtect(16); // 12 needed, round up for overhang
                emit32(X64_jp, target ? target - _nIns : 0);
                emit32(X64_jne, target ? target - _nIns : 0);
                patch = _nIns;
            } else {
                // jp skip (2byte)
                // jeq target
                // skip: ...
                underrunProtect(16); // 7 needed but we write 2 instr
                NIns *skip = _nIns;
                emit32(X64_je, target ? target - _nIns : 0);
                patch = _nIns;
                emit8(X64_jp8, skip - _nIns);
            }
        }
        else {
            if (condop == LIR_flt) {
                condop = LIR_fgt;
                LIns *t = a; a = b; b = t;
            } else if (condop == LIR_fle) {
                condop = LIR_fge;
                LIns *t = a; a = b; b = t;
            }
            X64Opcode xop;
            if (condop == LIR_fgt)
                xop = onFalse ? X64_jbe : X64_ja;
            else
                xop = onFalse ? X64_jb : X64_jae;
            underrunProtect(8);
            emit32(xop, target ? target - _nIns : 0);
            patch = _nIns;
        }
        fcmp(a, b);
        return patch;
    }

    void Assembler::asm_fcond(LIns *ins) {
        LOpcode op = ins->opcode();
        LIns *a = ins->oprnd1();
        LIns *b = ins->oprnd2();
        if (op == LIR_feq) {
            // result = ZF & !PF, must do logic on flags
            // r = al|bl|cl|dl, can only use rh without rex prefix
            Register r = prepResultReg(ins, 1<<RAX|1<<RCX|1<<RDX|1<<RBX);
            emitrr(X64_movzx8, r, r);                   // movzx8   r,rl     r[8:63] = 0
            emit(X86_and8r | uint64_t(r<<3|(r|4))<<56); // and      rl,rh    rl &= rh
            emit(X86_setnp | uint64_t(r|4)<<56);        // setnp    rh       rh = !PF
            emit(X86_sete  | uint64_t(r)<<56);          // sete     rl       rl = ZF
        } else {
            if (op == LIR_flt) {
                op = LIR_fgt;
                LIns *t = a; a = b; b = t;
            } else if (op == LIR_fle) {
                op = LIR_fge;
                LIns *t = a; a = b; b = t;
            }
            Register r = prepResultReg(ins, GpRegs); // x64 can use any GPR as setcc target
            emitrr(X64_movzx8, r, r);
            emitr1(op == LIR_fgt ? X64_seta : X64_setae, r);
        }
        fcmp(a, b);
    }

    void Assembler::fcmp(LIns *a, LIns *b) {
        Reservation *resva, *resvb;
        findRegFor2(FpRegs, a, resva, b, resvb);
        emitprr(X64_ucomisd, resva->reg, resvb->reg);
    }

    void Assembler::asm_restore(LIns *ins, Reservation *resv, Register r) {
        (void) r;
        if (ins->isop(LIR_alloc)) {
            int d = disp(resv);
            emitrm(X64_leaqrm, r, d, FP);
        }
        else if (ins->isconst()) {
            if (!resv->arIndex) {
                reserveFree(ins);
            }
            emit_int(r, ins->constval());
        }
        else if (ins->isconstq() && IsGpReg(r)) {
            if (!resv->arIndex) {
                reserveFree(ins);
            }
            emit_quad(r, ins->constvalq());
        }
        else {
            int d = findMemFor(ins);
            if (IsFpReg(r)) {
                NanoAssert(ins->isQuad());
                // load 64bits into XMM.  don't know if double or int64, assume double.
                emitprm32(X64_movsdrm, r, d, FP);
            } else if (ins->isQuad()) {
                emitrm(X64_movqrm, r, d, FP);
            } else {
                emitrm(X64_movlrm, r, d, FP);
            }
        }
        verbose_only(
            if (_verbose)
                outputf("        restore %s",_thisfrag->lirbuf->names->formatRef(ins));
        )
    }
    
    void Assembler::asm_cond(LIns *ins) {
        LOpcode op = ins->opcode();         
        // unlike x86-32, with a rex prefix we can use any GP register as an 8bit target
        Register r = prepResultReg(ins, GpRegs);
        // SETcc only sets low 8 bits, so extend 
        emitrr(X64_movzx8, r, r);
        X64Opcode xop;
        switch (op) {
        default:
            TODO(cond);
        case LIR_qeq:
        case LIR_eq:    xop = X64_sete;     break;
        case LIR_qlt:
        case LIR_lt:    xop = X64_setl;     break;
        case LIR_qle:
        case LIR_le:    xop = X64_setle;    break;
        case LIR_qgt:
        case LIR_gt:    xop = X64_setg;     break;
        case LIR_qge:
        case LIR_ge:    xop = X64_setge;    break;
        case LIR_qult:
        case LIR_ult:   xop = X64_setb;     break;
        case LIR_qule:
        case LIR_ule:   xop = X64_setbe;    break;
        case LIR_qugt:
        case LIR_ugt:   xop = X64_seta;     break;
        case LIR_quge:
        case LIR_uge:   xop = X64_setae;    break;
        case LIR_ov:    xop = X64_seto;     break;
        case LIR_cs:    xop = X64_setc;     break;
        }
        emitr1(xop, r);
        asm_cmp(ins);
    }

    void Assembler::asm_ret(LIns *ins) {
        JMP(_epilogue);
        assignSavedParams();
        LIns *value = ins->oprnd1();
        Register r = ins->isop(LIR_ret) ? RAX : XMM0;
        findSpecificRegFor(value, r);
    }

    void Assembler::asm_nongp_copy(Register d, Register s) {
        if (!IsFpReg(d) && IsFpReg(s)) {
            // gpr <- xmm: use movq r/m64, xmm (66 REX.W 0F 7E /r)
            emitprr(X64_movqrx, s, d);
        } else if (IsFpReg(d) && IsFpReg(s)) {
            // xmm <- xmm: use movsd
            emitprr(X64_movsdrr, d, s);
        } else {
            // xmm <- gpr: use movq xmm, r/m64 (66 REX.W 0F 6E /r)
            emitprr(X64_movqxr, d, s);
        }
    }

    void Assembler::regalloc_load(LIns *ins, Register &rr, int32_t &dr, Register &rb) {
        dr = ins->oprnd2()->constval();
        LIns *base = ins->oprnd1();
        rb = getBaseReg(base, dr, BaseRegs);
        Reservation *resv = getresv(ins);
        if (resv && (rr = resv->reg) != UnknownReg) {
            // keep already assigned register
            freeRsrcOf(ins, false);
        } else {
            // use a gpr in case we're copying a non-double
            rr = prepResultReg(ins, GpRegs & ~rmask(rb));
        }
    }

    void Assembler::asm_load64(LIns *ins) {
        Register rr, rb;
        int32_t dr;
        regalloc_load(ins, rr, dr, rb);
        if (IsGpReg(rr)) {
            // general 64bit load, 32bit const displacement
            emitrm(X64_movqrm, rr, dr, rb);
        } else {
            // load 64bits into XMM.  don't know if double or int64, assume double.
            emitprm32(X64_movsdrm, rr, dr, rb);
        }
    }

    void Assembler::asm_ld(LIns *ins) {
        NanoAssert(!ins->isQuad());
        Register r, b;
        int32_t d;
        regalloc_load(ins, r, d, b);
        emitrm(X64_movlrm, r, d, b);
    }
 
    void Assembler::asm_store64(LIns *value, int d, LIns *base) {
        NanoAssert(value->isQuad());
        Register b = getBaseReg(base, d, BaseRegs);

        // if we have to choose a register, use a GPR, but not the base reg
        Reservation *resv = getresv(value);
        Register r;
        if (!resv || (r = resv->reg) == UnknownReg) {
            r = findRegFor(value, GpRegs & ~rmask(b));
        }

        if (IsGpReg(r)) {
            // gpr store
            emitrm(X64_movqmr, r, d, b);
        }
        else {
            // xmm store
            emitprm32(X64_movsdmr, r, d, b);
        }
    }

    void Assembler::asm_store32(LIns *value, int d, LIns *base) {
        NanoAssert(!value->isQuad());
        Register b = getBaseReg(base, d, BaseRegs);
        Register r = findRegFor(value, GpRegs & ~rmask(b));

        // store 32bits to 64bit addr.  use rex so we can use all 16 regs
        emitrm(X64_movlmr, r, d, b);
    }

    void Assembler::emit_int(Register r, int32_t v) {
        underrunProtect(4+8); // imm32 + worst case instr len
        ((int32_t*)_nIns)[-1] = v;
        _nIns -= 4;
        emitr(X64_movi, r);
    }

    void Assembler::emit_quad(Register r, uint64_t v) {
        NanoAssert(IsGpReg(r));
        underrunProtect(8+8); // imm64 + worst case instr len
        ((uint64_t*)_nIns)[-1] = v;
        _nIns -= 8;
        emitr(X64_movqi, r);
    }

    void Assembler::asm_int(LIns *ins) {
        Register r = prepResultReg(ins, GpRegs);
        emit_int(r, ins->constval());
    }

    void Assembler::asm_quad(LIns *ins) {
        Register r = prepResultReg(ins, GpRegs);
        emit_quad(r, ins->constvalq());
    }

    void Assembler::asm_qjoin(LIns*) {
        TODO(asm_qjoin);
    }

    Register Assembler::asm_prep_fcall(Reservation*, LIns *ins) {
        return prepResultReg(ins, rmask(XMM0));
    }

    void Assembler::asm_param(LIns *ins) {
        uint32_t a = ins->imm8();
        uint32_t kind = ins->imm8b();
        if (kind == 0) {
            // ordinary param
            // first six args always in registers for mac x64
            if (a < 6) {
                // incoming arg in register
                prepResultReg(ins, rmask(argRegs[a]));
            } else {
                // todo: support stack based args, arg 0 is at [FP+off] where off
                // is the # of regs to be pushed in genProlog()
                TODO(asm_param_stk);
            }
        }
        else {
            // saved param
            prepResultReg(ins, rmask(savedRegs[a]));
        }
    }

    NIns* Assembler::asm_adjustBranch(NIns*, NIns*) {
        TODO(asm_adjustBranch);
        return 0;
    }

    // register allocation for 2-address style unary ops of the form R = (op) A
    void Assembler::regalloc_unary(LIns *ins, RegisterMask allow, Register &rr, Register &ra) {
        LIns *a = ins->oprnd1();
        rr = prepResultReg(ins, allow);
        Reservation* rA = getresv(a);
        // if this is last use of a in reg, we can re-use result reg
        if (rA == 0 || (ra = rA->reg) == UnknownReg) {
            ra = findSpecificRegFor(a, rr);
        } else if (!(rmask(ra) & allow)) {
            TODO(unary_ra);
        } else {
            // rA already has a register assigned.
        }
    }

    void Assembler::asm_fneg(LIns *ins) {
        Register rr = prepResultReg(ins, FpRegs);
        Register ra = findRegFor(ins->oprnd1(), FpRegs & ~rmask(rr));
        // xor r,r
        // r -= a
        emitprr(X64_subsd, rr, ra);
        emitprr(X64_pxor, rr, rr);        // pxor xmmr,xmmr to set r = 0
    }

    void Assembler::asm_qhi(LIns*) {
        TODO(asm_qhi);
    }

    void Assembler::asm_qlo(LIns *ins) {
        Register rr, ra;
        regalloc_unary(ins, GpRegs, rr, ra);
        NanoAssert(IsGpReg(ra));
        emitrr(X64_movlr, rr, ra); // 32bit mov zeros the upper 32bits of the target
    }

    void Assembler::asm_spill(Register rr, int d, bool /*pop*/, bool quad) {
        if (d) {
            if (!IsFpReg(rr)) {
                X64Opcode xop = quad ? X64_movqmr : X64_movlmr;
                emitrm(xop, rr, d, FP);
            } else {
                // store 64bits from XMM to memory
                NanoAssert(quad);
                emitprm32(X64_movsdmr, rr, d, FP);
            }
        }
    }

    void Assembler::asm_loop(LIns*, NInsList&) {
        TODO(asm_loop);
    }

    NIns* Assembler::genPrologue() {
        // activation frame is 4 bytes per entry even on 64bit machines
        uint32_t stackNeeded = _activation.highwatermark * 4;

        uint32_t stackPushed =
            sizeof(void*) + // returnaddr
            sizeof(void*); // ebp
        uint32_t aligned = alignUp(stackNeeded + stackPushed, NJ_ALIGN_STACK);
        uint32_t amt = aligned - stackPushed;

        // Reserve stackNeeded bytes, padded
        // to preserve NJ_ALIGN_STACK-byte alignment.
        if (amt) {
            emit32(X64_subspi, amt);
        }

        verbose_only( outputAddr=true; asm_output("[patch entry]"); )
        NIns *patchEntry = _nIns;
        MR(FP, RSP);            // Establish our own FP.
        emitr(X64_pushr, FP);   // Save caller's FP.

        // align the entry point
        // todo: the intel optimization guide suggests canonical nop 
        // instructions for sizes from 1..9; use them!
        underrunProtect(8);
        int code_align = (intptr_t)_nIns & 7;
        if (code_align) {
            static uint64_t nops[8] = {
                0, X64_nop1, X64_nop2, X64_nop3, X64_nop4, X64_nop5, X64_nop6, X64_nop7
            };
            emit(nops[code_align]);
        }
        return patchEntry;
    }

    NIns* Assembler::genEpilogue() {
        // mov rsp, rbp
        // pop rbp
        // ret
        emit(X64_ret);
        emit(X64r(X64_pop, RBP));
        MR(RSP, RBP);
        return _nIns;
    }

    void Assembler::nMarkExecute(Page* page, int flags)
    {
        NanoAssert(sizeof(Page) == NJ_PAGE_SIZE);
        #if defined WIN32 || defined WIN64
            DWORD dwIgnore;
            static const DWORD kProtFlags[4] = 
            {
                PAGE_READONLY,          // 0
                PAGE_READWRITE,         // PAGE_WRITE
                PAGE_EXECUTE_READ,      // PAGE_EXEC
                PAGE_EXECUTE_READWRITE  // PAGE_EXEC|PAGE_WRITE
            };
            DWORD prot = kProtFlags[flags & (PAGE_WRITE|PAGE_EXEC)];
            BOOL res = VirtualProtect(page, NJ_PAGE_SIZE, prot, &dwIgnore);
            if (!res)
            {
                // todo: we can't abort or assert here, we have to fail gracefully.
                NanoAssertMsg(false, "FATAL ERROR: VirtualProtect() failed\n");
            }
        #elif defined AVMPLUS_UNIX || defined AVMPLUS_MAC
            static const int kProtFlags[4] = 
            {
                PROT_READ,                      // 0
                PROT_READ|PROT_WRITE,           // PAGE_WRITE
                PROT_READ|PROT_EXEC,            // PAGE_EXEC
                PROT_READ|PROT_WRITE|PROT_EXEC  // PAGE_EXEC|PAGE_WRITE
            };
            int prot = kProtFlags[flags & (PAGE_WRITE|PAGE_EXEC)];
            intptr_t addr = (intptr_t)page;
            addr &= ~((uintptr_t)NJ_PAGE_SIZE - 1);
            NanoAssert(addr == (intptr_t)page);
            //#if defined SOLARIS
            //if (mprotect((char *)addr, NJ_PAGE_SIZE, prot) == -1) 
            //#elif defined AVMPLUS_MAC
            //task_t task = mach_task_self();
            //if (vm_protect(task, addr, NJ_PAGE_SIZE, true, prot) == -1)
            //#else
            if (mprotect((void *)addr, NJ_PAGE_SIZE, prot) == -1) 
            //#endif
            {
                // todo: we can't abort or assert here, we have to fail gracefully.
                NanoAssertMsg(false, "FATAL ERROR: mprotect(PROT_EXEC) failed\n");
                abort();
            }
        #else
            (void)page;
        #endif
    }

    void Assembler::nRegisterResetAll(RegAlloc &a) {
        // add scratch registers to our free list for the allocator
        a.clear();
        a.used = 0;
        a.free = 0xffffffff & ~(1<<RSP | 1<<RBP);
        debug_only( a.managed = a.free; )
    }

    void Assembler::nPatchBranch(NIns *patch, NIns *target) {
        NIns *next = 0;
        if (patch[0] == 0xE9) {
            // jmp disp32
            next = patch+5;
        } else if (patch[0] == 0x0F && (patch[1] & 0xF0) == 0x80) {
            // jcc disp32
            next = patch+6;
        } else {
            TODO(unknown_patch);
        }
        NanoAssert(((int32_t*)next)[-1] == 0);
        NanoAssert(isS32(target - next));
        ((int32_t*)next)[-1] = target - next;
        if (next[0] == 0x0F && next[1] == 0x8A) {
            // code is jne<target>,jp<target>, for LIR_jf(feq)
            // we just patched the jne, now patch the jp.
            next += 6;
            NanoAssert(((int32_t*)next)[-1] == 0);
            NanoAssert(isS32(target - next));
            ((int32_t*)next)[-1] = target - next;
        }
    }

    Register Assembler::nRegisterAllocFromSet(RegisterMask set) {
    #if defined _WIN64
        DWORD tr;
        _BitScanForward(&tr, set);
        _allocator.free &= ~rmask((Register)tr);
        return (Register) tr;
    #else
        // gcc asm syntax
        Register r;
        asm("bsf    %1, %%eax\n\t"
            "btr    %%eax, %2\n\t"
            "movl   %%eax, %0\n\t"
            : "=m"(r) : "m"(set), "m"(_allocator.free) : "%eax", "memory");
        (void)set;
        return r;
    #endif
    }

    void Assembler::nFragExit(LIns*) {
        TODO(nFragExit);
    }

    void Assembler::nInit(AvmCore*)
    {}

    void Assembler::underrunProtect(ptrdiff_t bytes) {
        NanoAssertMsg(bytes<=LARGEST_UNDERRUN_PROT, "constant LARGEST_UNDERRUN_PROT is too small"); 
        NIns *pc = _nIns;
        NIns *top = (NIns*) &((Page*)pageTop(pc-1))->code[0];

    #if PEDANTIC
        // pedanticTop is based on the last call to underrunProtect; any time we call
        // underrunProtect and would use more than what's already protected, then insert
        // a page break jump.  Sometimes, this will be to a new page, usually it's just
        // the next instruction

        NanoAssert(pedanticTop >= top);
        if (pc - bytes < pedanticTop) {
            // no page break required, but insert a far branch anyway just to be difficult
            const int br_size = 8; // opcode + 32bit addr
            if (pc - bytes - br_size < top) {
                // really do need a page break
                verbose_only(if (_verbose) outputf("newpage %p:", pc);)
                _nIns = pageAlloc(_inExit);
            }
            // now emit the jump, but make sure we won't need another page break. 
            // we're pedantic, but not *that* pedantic.
            pedanticTop = _nIns - br_size;
            JMP(pc);
            pedanticTop = _nIns - bytes;
        }
    #else
        if (pc - bytes < top) {
            verbose_only(if (_verbose) outputf("newpage %p:", pc);)
            _nIns = pageAlloc(_inExit);
            // this jump will call underrunProtect again, but since we're on a new
            // page, nothing will happen.
            JMP(pc);
        }
    #endif
    }

    RegisterMask Assembler::hint(LIns *, RegisterMask allow) {
        return allow;
    }

    void Assembler::nativePageSetup() {
        if (!_nIns) {
            _nIns = pageAlloc();
            IF_PEDANTIC( pedanticTop = _nIns; )
        }
        if (!_nExitIns) {
            _nExitIns = pageAlloc(true);
        }
    }

    void Assembler::nativePageReset()
    {}

} // namespace nanojit

#endif // FEATURE_NANOJIT && NANOJIT_X64
