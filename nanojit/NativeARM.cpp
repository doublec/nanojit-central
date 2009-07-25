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
 * Portions created by the Initial Developer are Copyright (C) 2004-2007
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Adobe AS3 Team
 *   Vladimir Vukicevic <vladimir@pobox.com>
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

#include "nanojit.h"

#ifdef AVMPLUS_PORTING_API
#include "portapi_nanojit.h"
#endif

#ifdef UNDER_CE
#include <cmnintrin.h>
extern "C" bool blx_lr_broken();
#endif

#if defined(AVMPLUS_LINUX)
#include <asm/unistd.h>
extern "C" void __clear_cache(char *BEG, char *END);
#endif

#if defined FEATURE_NANOJIT && defined NANOJIT_ARM

namespace nanojit
{

#ifdef NJ_VERBOSE
const char* regNames[] = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","fp","ip","sp","lr","pc",
                          "d0","d1","d2","d3","d4","d5","d6","d7","s14"};
const char* condNames[] = {"eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le",""/*al*/,"nv"};
const char* shiftNames[] = { "lsl", "lsl", "lsr", "lsr", "asr", "asr", "ror", "ror" };
#endif

const Register Assembler::argRegs[] = { R0, R1, R2, R3 };
const Register Assembler::retRegs[] = { R0, R1 };
const Register Assembler::savedRegs[] = { R4, R5, R6, R7, R8, R9, R10 };

// --------------------------------
// ARM-specific utility functions.
// --------------------------------

// Calculate the number of leading zeroes in data.
uint32_t
Assembler::CountLeadingZeroes(uint32_t data)
{
    uint32_t    leading_zeroes;
#if defined(__ARMCC__)
    // ARMCC can do this with an intrinsic.
    leading_zeroes = __clz(data);
#elif defined(__GNUC__)
    // GCC can use inline assembler to insert a CLZ instruction.
    __asm (
        "   clz     %0, %1  \n"
        :   "=r"    (leading_zeroes)
        :   "r"     (data)
    );
#elif defined(WINCE)
    // WinCE can do this with an intrinsic.
    leading_zeroes = _CountLeadingZeros(data);
#else
    // Other platforms must fall back to a C routine. This won't be as
    // efficient as the CLZ instruction, but it is functional.
    uint32_t    try_shift;

    leading_zeroes = 0;

    // This loop does a bisection search rather than the obvious rotation loop.
    // This should be faster, though it will still be no match for CLZ.
    for (try_shift = 16; try_shift != 0; try_shift /= 2) {
        uint32_t    shift = leading_zeroes + try_shift;
        if (((data << shift) >> shift) == data) {
            leading_zeroes = shift;
        }
    }
#endif

    return leading_zeroes;
}

// --------------------------------
// Assembler functions.
// --------------------------------

void
Assembler::nInit(AvmCore*)
{
#if UNDER_CE
    blx_lr_bug = blx_lr_broken();
#else
    blx_lr_bug = 0;
#endif
}

NIns*
Assembler::genPrologue()
{
    /**
     * Prologue
     */

    // NJ_RESV_OFFSET is space at the top of the stack for us
    // to use for parameter passing (8 bytes at the moment)
    uint32_t stackNeeded = max_out_args + STACK_GRANULARITY * _activation.highwatermark;
    uint32_t savingCount = NumSavedRegs + 2;
    uint32_t savingMask = SavedRegs | rmask(FP) | rmask(LR);

    // so for alignment purposes we've pushed  return addr, fp, and savingCount registers
    uint32_t stackPushed = STACK_GRANULARITY * savingCount;
    uint32_t aligned = alignUp(stackNeeded + stackPushed, NJ_ALIGN_STACK);
    int32_t amt = aligned - stackPushed;

    // Make room on stack for what we are doing
    if (amt)
        asm_sub_imm(SP, SP, amt);

    verbose_only(
    if (_logc->lcbits & LC_Assembly) {
        outputf("         %p:",_nIns);
        output("         patch entry");
    })
    NIns *patchEntry = _nIns;

    MOV(FP, SP);
    PUSH_mask(savingMask);
    return patchEntry;
}

void
Assembler::nFragExit(LInsp guard)
{
    (void)guard;
#ifdef TM_MERGE
    SideExit *  exit = guard->record()->exit;
    Fragment *  frag = exit->target;

    bool        target_is_known = frag && frag->fragEntry;

    if (target_is_known) {
        // The target exists so we can simply emit a branch to its location.
        JMP_far(frag->fragEntry);
    } else {
        // The target doesn't exit yet, so emit a jump to the epilogue. If the
        // target is created later on, the jump will be patched.

        GuardRecord *   gr = guard->record();

        // Jump to the epilogue. This may get patched later, but JMP_far always
        // emits two instructions even when only one is required, so patching
        // will work correctly.
        JMP_far(_epilogue);

        // Load the guard record pointer into R2. We want it in R0 but we can't
        // do this at this stage because R0 is used for something else.
        // I don't understand why I can't load directly into R0. It works for
        // the JavaScript JIT but not for the Regular Expression compiler.
        // However, I haven't pushed this further as it only saves a single MOV
        // instruction in genEpilogue.
        LDi(R2, int(gr));

        // Set the jmp pointer to the start of the sequence so that patched
        // branches can skip the LDi sequence.
        gr->jmp = _nIns;
    }

#ifdef NJ_VERBOSE
    if (config.show_stats) {
        // load R1 with Fragment *fromFrag, target fragment
        // will make use of this when calling fragenter().
        int fromfrag = int((Fragment*)_thisfrag);
        LDi(argRegs[1], fromfrag);
    }
#endif

    // Pop the stack frame.
    MOV(SP, FP);
#endif
}

NIns*
Assembler::genEpilogue()
{
    // On v5 and above, this generates the following sequence:
    //   MOV SP,FP
    //   LDMFD SP!,{SavedRegs,FP,PC}
    // which will always handle interworking correctly.
    //
    // On v4T, LR is loaded instead of PC, and then a BX LR is executed.
    //
    // On v4 (and below), interworking is not required, and the v5+ code
    // sequence is used.
#if NJ_ARM_ARCH != NJ_ARM_V4T
    RegisterMask savingMask = SavedRegs | rmask(FP) | rmask(PC);
#else
    RegisterMask savingMask = SavedRegs | rmask(FP) | rmask(LR);
    BX(LR);
#endif
    POP_mask(savingMask);
    MOV(SP,FP);
    return _nIns;
}

/* gcc/linux use the ARM EABI; Windows CE uses the legacy abi.
 *
 * Under EABI:
 * - doubles are 64-bit aligned both in registers and on the stack.
 *   If the next available argument register is R1, it is skipped
 *   and the double is placed in R2:R3.  If R0:R1 or R2:R3 are not
 *   available, the double is placed on the stack, 64-bit aligned.
 * - 32-bit arguments are placed in registers and 32-bit aligned
 *   on the stack.
 *
 * Under legacy ABI:
 * - doubles are placed in subsequent arg registers; if the next
 *   available register is r3, the low order word goes into r3
 *   and the high order goes on the stack.
 * - 32-bit arguments are placed in the next available arg register,
 * - both doubles and 32-bit arguments are placed on stack with 32-bit
 *   alignment.
 */

#if TM_MERGE
void
Assembler::asm_arg(ArgSize sz, LInsp p, Register r)
{
    // should never be called -- the ARM-specific longer form of
    // asm_arg is used on ARM.
    NanoAssert(0);
}
#endif

/*
 * asm_arg will update r and stkd to indicate where the next
 * argument should go.  If r == UnknownReg, then the argument
 * is placed on the stack at stkd, and stkd is updated.
 *
 * Note that this currently doesn't actually use stkd on input,
 * except for figuring out alignment; it always pushes to SP.
 * See TODO in asm_call.
 */
void 
Assembler::asm_arg(ArgSize sz, LInsp arg, Register& r, int& stkd)
{
    if (sz == ARGSIZE_F) {
#ifdef NJ_SOFTFLOAT
        NanoAssert(arg->isop(LIR_qjoin));
#else
        Register fp_reg = findRegFor(arg, FpRegs);
        NanoAssert(fp_reg != UnknownReg);
#endif

#if NJ_ARM_EABI
        // arm eabi puts doubles only in R0:1 or R2:3, and 64bit aligned on the stack.
        if ((r == R1) || (r == R3)) r = nextreg(r);
#endif
        if (r < R3) {
            // put double in two registers
#ifdef NJ_SOFTFLOAT
            asm_regarg(ARGSIZE_LO, arg->oprnd1(), r);
            asm_regarg(ARGSIZE_LO, arg->oprnd2(), nextreg(r));
#else
            FMRRD(r, nextreg(r), fp_reg);
#endif
            r = Register(r+2);                
#ifndef NJ_ARM_EBAI
        } else if (r < R4) {
            // put LSW in R3, MSW on stack
#ifdef NJ_SOFTFLOAT
            asm_regarg(ARGSIZE_LO, arg->oprnd1(), r);
            asm_stkarg(arg->oprnd2(), stkd);
#else
            NanoAssert(stkd==0);
            STR(IP, SP, 0);
            FMRRD(r, IP, fp_reg);
#endif
            r = nextreg(r);
            stkd += 4;
#endif /* NJ_ARM_EABI */
        } else {
#ifdef NJ_ARM_EABI
            // put double on stack, 64bit aligned
            if ((stkd & 7) != 0) stkd += 4;
#endif
#ifdef NJ_SOFTFLOAT
            asm_stkarg(arg->oprnd1(), stkd);
            asm_stkarg(arg->oprnd2(), stkd+4);
#else
            asm_stkarg(arg, stkd);
#endif
            stkd += 8;
        }
    }
    else if (sz & ARGSIZE_MASK_INT) {
        // pre-assign registers R0-R3 for arguments (if they fit)
        if (r < R4) {
            asm_regarg(sz, arg, r);
            r = nextreg(r);
        } else {
            asm_stkarg(arg, stkd);
            stkd += 4;
        }
    }
    else {
        NanoAssert(sz == ARGSIZE_Q);
        // shouldn't have 64 bit int params on ARM
        NanoAssert(false);
    }
}

void 
Assembler::asm_regarg(ArgSize sz, LInsp p, Register r)
{
    NanoAssert(r != UnknownReg);
    if (sz & ARGSIZE_MASK_INT)
    {
        // arg goes in specific register
        if (p->isconst()) {
            int c = p->imm32();
            LDi(r, c);
        } else {
            Reservation* rA = getresv(p);
            if (rA) {
                if (rA->reg == UnknownReg) {
                    // load it into the arg reg
                    int d = findMemFor(p);
                    if (p->isop(LIR_alloc)) {
                        asm_add_imm(r, FP, d, 0);
                    } else {
                        LDR(r, FP, d);
                    }
                } else {
                    // it must be in a saved reg
                    MOV(r, rA->reg);
                }
            }
            else {
                // this is the last use, so fine to assign it
                // to the scratch reg, it's dead after this point.
                findSpecificRegFor(p, r);
            }
        }
    }
    else if (sz == ARGSIZE_Q) {
        // 64 bit integer argument - should never happen on ARM
        NanoAssert(false);
    }
    else
    {
        NanoAssert(sz == ARGSIZE_F);
        // fpu argument in register - should never happen since FPU
        // args are converted to two 32-bit ints on ARM
        NanoAssert(false);
    }
}

void
Assembler::asm_stkarg(LInsp arg, int stkd)
{
    Reservation* argRes = getresv(arg);
    bool quad = arg->isQuad();

    if (argRes && argRes->reg != UnknownReg) {
#ifdef NJ_ARM_VFP
        if (!quad) {
            STR(argRes->reg, SP, stkd);
        } else {
            FSTD(argRes->reg, SP, stkd);
        }
#else
        STR(argRes->reg, SP, stkd);
#endif
    } else {
        int d = findMemFor(arg);
        if (!quad) {
            STR(IP, SP, stkd);
            if (arg->isop(LIR_alloc)) {
                asm_add_imm(IP, FP, d, 0);
            } else {
                LDR(IP, FP, d);
            }
        } else {
            STR_preindex(IP, SP, stkd+4);
            LDR(IP, FP, d+4);
            STR_preindex(IP, SP, stkd);
            LDR(IP, FP, d);
        }
    }
}

void
Assembler::asm_call(LInsp ins)
{
    const CallInfo* call = ins->callInfo();
    bool needToLoadAddr = false;
    ArgSize sizes[MAXARGS];
    uint32_t argc = call->get_sizes(sizes);
    bool indirect = call->isIndirect();

#ifdef NJ_SOFTFLOAT
    NanoAssert(ins->isop(LIR_icall));
#endif

#ifdef NJ_ARM_VFP
    // Sort out where a VFP result goes. See comments in
    // asm_prep_fcall() for more details as to why this is
    // necessary here for floating point calls, but not for
    // integer calls.
    Reservation *callRes = getresv(ins);
    if (callRes) { // If callRes==NULL, the result is discarded
        Register rr = callRes->reg;
        if (rr == UnknownReg) {
            // If the result doesn't have a register allocated, then
            // store R0,R1 directly to the stack slot
        int d = disp(callRes);
            NanoAssert(d != 0);
            freeRsrcOf(ins, false);
            STR(R1, FP, d+4);
            STR(R0, FP, d+0);
        } else {
            // If the result does have a register allocated, move it
            // into the appropriate register, and allow prepResultReg()
            // to work out if any other action (e.g. storing to stack)
            // is necessary.
            NanoAssert(IsFpReg(rr));
            prepResultReg(ins, rmask(rr));
            FMDRR(rr,R0,R1);
        }
    }
#endif

    if (!indirect) {
        verbose_only(if (_logc->lcbits & LC_Assembly)
            outputf("        %p:", _nIns);
        )
        // Direct call: on v5 and above (where the calling sequence doesn't
        // corrupt LR until the actual branch instruction), we can avoid an
        // interlock in the "long" branch sequence by manually loading the
        // target address into LR ourselves before setting up the parameters
        // in other registers.
#if NJ_ARM_ARCH >= NJ_ARM_V5
        needToLoadAddr = BL_noload((NIns*)call->_address, LR);
#else
        BL((NIns*)call->_address);
#endif
    } else {
        // Indirect call: we assign the address arg to LR since it's not
        // used for regular arguments, and is otherwise scratch since it's
        // clobberred by the call. On v4/v4T, where we have to manually do
        // the equivalent of a BLX, move LR into IP before corrupting LR
        // with the return address.
#if NJ_ARM_ARCH >= NJ_ARM_V5
        if (blx_lr_bug) {
            // workaround for msft device emulator bug (blx lr emulated as no-op)
            underrunProtect(8);
            BLX(IP);
            MOV(IP,LR);
        } else {
            BLX(LR);
        }
#else
        underrunProtect(8); // keep next instr (BX or MOV PC,IP) and MOV LR,PC in the same page
    #if NJ_ARM_ARCH == NJ_ARM_V4T
        BX(IP);
    #else
        MOV(PC,IP);
    #endif
        MOV(LR,PC);
        MOV(IP,LR);
#endif
        asm_regarg(ARGSIZE_LO, ins->arg(--argc), LR);
    }

    Register r = R0;
    int stkd = 0;

    // XXX TODO we should go through the args and figure out how much
    // stack space we'll need, allocate it up front, and then do
    // SP-relative stores using stkd instead of doing STR_preindex for
    // every stack write like we currently do in asm_arg.

    for(uint32_t i = 0; i < argc; i++) {
        uint32_t j = argc - i - 1;
        ArgSize sz = sizes[j];
        LInsp arg = ins->arg(j);

#ifdef TM_MERGE
        NanoAssert(r < R4 || r == UnknownReg);

#ifdef NJ_ARM_EABI
        if (sz == ARGSIZE_F) {
            if (r == R1)
                r = R2;
            else if (r == R3)
                r = UnknownReg;
        }
#endif
#endif
        asm_arg(sz, arg, r, stkd);
    }
    if (stkd > max_out_args)
        max_out_args = stkd;

    if (needToLoadAddr)
        LDi(LR, (int32_t)call->_address);
}

Register
Assembler::nRegisterAllocFromSet(int set)
{
    // The CountLeadingZeroes function will use the CLZ instruction where
    // available. In other cases, it will fall back to a (slower) C
    // implementation.
    Register r = (Register)(31-CountLeadingZeroes(set));
    _allocator.free &= ~rmask(r);
    return r;
}

void
Assembler::nRegisterResetAll(RegAlloc& a)
{
    // add scratch registers to our free list for the allocator
    a.clear();
    a.free = rmask(R0) | rmask(R1) | rmask(R2) | rmask(R3)
           | rmask(LR)
#ifdef NJ_ARM_VFP
           | rmask(D0) | rmask(D1) | rmask(D2) | rmask(D3)
           | rmask(D4) | rmask(D5) | rmask(D6)
#endif
           | SavedRegs;
    debug_only(a.managed = a.free);
    max_out_args = 0;
}

void
Assembler::nPatchBranch(NIns* branch, NIns* target)
{
    // Patch the jump in a loop

    int32_t offset = PC_OFFSET_FROM(target, branch);

    //avmplus::AvmLog("---patching branch at 0x%08x to location 0x%08x (%d-0x%08x)\n", branch, target, offset, offset);

    // We have 2 words to work with here -- if offset is in range of a 24-bit
    // relative jump, emit that; otherwise, we do a pc-relative load into pc.
    if (isS24(offset>>2)) {
        // write a new instruction that preserves the condition of what's there.
        NIns cond = *branch & 0xF0000000;
        *branch = (NIns)( cond | (0xA<<24) | ((offset>>2) & 0xFFFFFF) );
    } else {
        // update const-addr, branch instruction is:
        // LDRcc pc, [pc, #off-to-const-addr]
        NanoAssert((*branch & 0x0F7FF000) == 0x051FF000);

        NIns *addr = branch+2;
        int offset = (*branch & 0xFFF) / sizeof(NIns);

        if (*branch & (1<<23)) {
            addr += offset;
        } else {
            addr -= offset;
        }

        *addr = (NIns) target;
    }
}

RegisterMask
Assembler::hint(LIns* i, RegisterMask allow /* = ~0 */)
{
    uint32_t op = i->opcode();
    int prefer = ~0;
    if (op==LIR_icall)
        prefer = rmask(R0);
    else if (op == LIR_callh)
        prefer = rmask(R1);
    else if (op == LIR_param) {
        if (i->paramArg() < 4)
            prefer = rmask(argRegs[i->paramArg()]);
    }
    if (_allocator.free & allow & prefer)
        allow &= prefer;
    return allow;
}

void
Assembler::asm_qjoin(LIns *ins)
{
    int d = findMemFor(ins);
    NanoAssert(d);
    LIns* lo = ins->oprnd1();
    LIns* hi = ins->oprnd2();

    Register r = findRegFor(hi, GpRegs);
    STR(r, FP, d+4);

    // okay if r gets recycled.
    r = findRegFor(lo, GpRegs);
    STR(r, FP, d);
    freeRsrcOf(ins, false); // if we had a reg in use, emit a ST to flush it to mem
}

void
Assembler::asm_store32(LIns *value, int dr, LIns *base)
{
    Reservation *rA, *rB;
    Register ra, rb;
    if (base->isop(LIR_alloc)) {
        rb = FP;
        dr += findMemFor(base);
        ra = findRegFor(value, GpRegs);
    } else {
        findRegFor2(GpRegs, value, rA, base, rB);
        ra = rA->reg;
        rb = rB->reg;
    }
    STR(ra, rb, dr);
}

void
Assembler::asm_restore(LInsp i, Reservation *resv, Register r)
{
    if (i->isop(LIR_alloc)) {
        int d = disp(resv);
        asm_add_imm(r, FP, d, 0);
    }
    else if (i->isconst()) {
        if (!resv->arIndex) {
            i->resv()->clear();
        }
        LDi(r, i->imm32());
    }
    else {
        int d = findMemFor(i);
#ifdef NJ_ARM_VFP
        if (IsFpReg(r)) {
            if (isS8(d >> 2)) {
                FLDD(r, FP, d);
            } else {
                FLDD(r, IP, 0);
                asm_add_imm(IP, FP, d, 0);
            }
        } else {
            LDR(r, FP, d);
        }
#else
        LDR(r, FP, d);
#endif

        verbose_only(
            asm_output("        restore %s",_thisfrag->lirbuf->names->formatRef(i));
        )
    }
}

void
Assembler::asm_spill(Register rr, int d, bool pop, bool quad)
{
    (void) pop;
    (void) quad;
    if (d) {
#ifdef NJ_ARM_VFP
        if (IsFpReg(rr)) {
            if (isS8(d >> 2)) {
                FSTD(rr, FP, d);
            } else {
                FSTD(rr, IP, 0);
                asm_add_imm(IP, FP, d, 0);
            }
        } else {
            STR(rr, FP, d);
        }
#else
        STR(rr, FP, d);
#endif
    }
}

void
Assembler::asm_load64(LInsp ins)
{
    ///asm_output("<<< load64");

    LIns* base = ins->oprnd1();
    int offset = ins->disp();

#ifdef NJ_ARM_VFP
    Register rr = prepResultReg(ins, FpRegs);
    Register rb = findRegFor(base, GpRegs);

    NanoAssert(IsFpReg(rr));

    if (isS8(offset >> 2) && (offset&3) == 0) {
        FLDD(rr,rb,offset);
    } else {
            FLDD(rr,IP,0);
            asm_add_imm(IP, rb, offset, 0);
    }
#else
    Reservation *resv = getresv(ins);
    int d = disp(resv);

    NanoAssert(resv->reg == UnknownReg && d != 0);
    Register rb = findRegFor(base, GpRegs);
    // *(FP+dr) <- *(rb+db)
    asm_mmq(FP, d, rb, offset);

    // bug https://bugzilla.mozilla.org/show_bug.cgi?id=477228
    // make sure we release the instruction's stack slot *after*
    // any findRegFor() since that call can trigger a spill
    freeRsrcOf(ins, false);
#endif

    //asm_output(">>> load64");
}

void
Assembler::asm_store64(LInsp value, int dr, LInsp base)
{
    //asm_output("<<< store64 (dr: %d)", dr);

    Register rb = findRegFor(base, GpRegs);
    if (value->isconstq()) {
        const int32_t* p = (const int32_t*) (value-2);
        STR(IP, rb, dr);
        LDi(IP, p[0]);
        STR(IP, rb, dr+4);
        LDi(IP, p[1]);
        return;
    }

#ifdef NJ_ARM_VFP
    Register rv = findRegFor(value, FpRegs);

    NanoAssert(rb != UnknownReg);
    NanoAssert(rv != UnknownReg);

    Register baseReg = rb;
    intptr_t baseOffset = dr;

    if (!isS8(dr)) {
        baseReg = IP;
        baseOffset = 0;
    }

    FSTD(rv, baseReg, baseOffset);

    if (!isS8(dr)) {
        asm_add_imm(IP, rb, dr, 0);
    }

    // if it's a constant, make sure our baseReg/baseOffset location
    // has the right value
    if (value->isconstq()) {
        const int32_t* p = (const int32_t*) (value-2);

        underrunProtect(16);

        asm_quad_nochk(rv, value->imm64_0(), value->imm64_1());
    }
#else
    int da = findMemFor(value);
    asm_mmq(rb, dr, FP, da);
#endif
    //asm_output(">>> store64");
}

#ifdef NJ_ARM_VFP
// stick a quad into register rr, where p points to the two
// 32-bit parts of the quad, optinally also storing at FP+d
void
Assembler::asm_quad_nochk(Register rr, int32_t imm64_0, int32_t imm64_1)
{
    // We're not going to use a slot, because it might be too far
    // away.  Instead, we're going to stick a branch in the stream to
    // jump over the constants, and then load from a short PC relative
    // offset.

    // stream should look like:
    //    branch A
    //    imm64_0
    //    imm64_1
    // A: FLDD PC-16

    FLDD(rr, PC, -16);

    *(--_nIns) = (NIns) imm64_1;
    *(--_nIns) = (NIns) imm64_0;

    B_nochk(_nIns+2);
}
#endif

void
Assembler::asm_quad(LInsp ins)
{
    //asm_output(">>> asm_quad");

    Reservation *res = getresv(ins);
    int d = disp(res);

    const int32_t* p = (const int32_t*) (ins-2);

    freeRsrcOf(ins, false);
#ifdef NJ_ARM_VFP
    Register rr = res->reg;
    NanoAssert(d || rr != UnknownReg);

    if (rr != UnknownReg) {
        if (d)
            FSTD(rr, FP, d);

        underrunProtect(16);
        asm_quad_nochk(rr, ins->imm64_0(), ins->imm64_1());
    } else
#endif
    {
        NanoAssert(d);
        // asm_mmq might spill a reg, so don't call it;
        // instead do the equivalent directly.
        //asm_mmq(FP, d, PC, -16);

        STR(IP, FP, d+4);
        LDi(IP, p[1]);
        STR(IP, FP, d);
        LDi(IP, p[0]);
    }

    //asm_output("<<< asm_quad");
}

void
Assembler::asm_nongp_copy(Register r, Register s)
{
#ifdef NJ_ARM_VFP
    if ((rmask(r) & FpRegs) && (rmask(s) & FpRegs)) {
        // fp->fp
        FCPYD(r, s);
    } else if ((rmask(r) & GpRegs) && (rmask(s) & FpRegs)) {
        // fp->gp
        // who's doing this and why?
        NanoAssert(0);
        // FMRS(r, loSingleVfp(s));
    } else {
        NanoAssert(0);
    }
#else
    (void)r;
    (void)s;
    NanoAssert(0);
#endif
}

Register
Assembler::asm_binop_rhs_reg(LInsp)
{
    return UnknownReg;
}

/**
 * copy 64 bits: (rd+dd) <- (rs+ds)
 */
void
Assembler::asm_mmq(Register rd, int dd, Register rs, int ds)
{
    // The value is either a 64bit struct or maybe a float that isn't live in
    // an FPU reg.  Either way, don't put it in an FPU reg just to load & store
    // it.
    // This operation becomes a simple 64-bit memcpy.

    // In order to make the operation optimal, we will require two GP
    // registers. We can't allocate a register here because the caller may have
    // called freeRsrcOf, and allocating a register here may cause something
    // else to spill onto the stack which has just be conveniently freed by
    // freeRsrcOf (resulting in stack corruption).
    //
    // Falling back to a single-register implementation of asm_mmq is better
    // than adjusting the callers' behaviour (to allow us to allocate another
    // register here) because spilling a register will end up being slower than
    // just using the same register twice anyway.
    //
    // Thus, if there is a free register which we can borrow, we will emit the
    // following code:
    //  LDR rr, [rs, #ds]
    //  LDR ip, [rs, #(ds+4)]
    //  STR rr, [rd, #dd]
    //  STR ip, [rd, #(dd+4)]
    // (Where rr is the borrowed register.)
    //
    // If there is no free register, don't spill an existing allocation. Just
    // do the following:
    //  LDR ip, [rs, #ds]
    //  STR ip, [rd, #dd]
    //  LDR ip, [rs, #(ds+4)]
    //  STR ip, [rd, #(dd+4)]

    // Ensure that the PC is not used as either base register. The instruction
    // generation macros call underrunProtect, and a side effect of this is
    // that we may be pushed onto another page, so the PC is not a reliable
    // base register.
    NanoAssert(rs != PC);
    NanoAssert(rd != PC);

    // Find the list of free registers from the allocator's free list and the
    // GpRegs mask. This excludes any floating-point registers that may be on
    // the free list.
    RegisterMask    free = _allocator.free & AllowableFlagRegs;

    if (free) {
        // There is at least one register on the free list, so grab one for
        // temporary use. There is no need to allocate it explicitly because
        // we won't need it after this function returns.

        // The CountLeadingZeroes can be used to quickly find a set bit in the
        // free mask.
        Register    rr = (Register)(31-CountLeadingZeroes(free));

        // Note: Not every register in GpRegs is usable here. However, these
        // registers will never appear on the free list.
#ifdef TM_MERGE
        // The above statement and asserts below are not true LR does appear
        // on the free list
        NanoAssert((free & rmask(PC)) == 0);
        NanoAssert((free & rmask(LR)) == 0);
        NanoAssert((free & rmask(SP)) == 0);
        NanoAssert((free & rmask(IP)) == 0);
        NanoAssert((free & rmask(FP)) == 0);
#endif
        // Emit the actual instruction sequence.

        STR(IP, rd, dd+4);
        STR(rr, rd, dd);
        LDR(IP, rs, ds+4);
        LDR(rr, rs, ds);
    } else {
        // There are no free registers, so fall back to using IP twice.
        STR(IP, rd, dd+4);
        LDR(IP, rs, ds+4);
        STR(IP, rd, dd);
        LDR(IP, rs, ds);
    }
}

void
Assembler::nativePageReset()
{
    _nExitSlot = 0;
}

void
Assembler::nativePageSetup()
{
    if (!_nIns)
        codeAlloc();
    if (!_nExitIns)
        codeAlloc(true);

    // constpool starts at top of page and goes down,
    // code starts at bottom of page and moves up
    if (!_nSlot)
        _nSlot = codeStart;
    if (!_nExitSlot)
        _nExitSlot = exitStart;
}

void
Assembler::underrunProtect(int bytes)
{
    NanoAssertMsg(bytes<=LARGEST_UNDERRUN_PROT, "constant LARGEST_UNDERRUN_PROT is too small");
    NanoAssert(_nSlot != 0 && int(_nIns)-int(_nSlot) <= 4096);
    uintptr_t top = uintptr_t(_nSlot);
    uintptr_t pc = uintptr_t(_nIns);
    if (pc - bytes < top)
    {
        verbose_only(if (_logc->lcbits & LC_Assembly) outputf("        %p:", _nIns);)
        NIns* target = _nIns;
        codeAlloc(_inExit);
        _nSlot = _inExit ? exitStart : codeStart;

        // _nSlot points to the first empty position in the new code block
        // _nIns points just past the last empty position.
        // Assume B_nochk won't ever try to write to _nSlot. See B_cond_chk macro.
        B_nochk(target);
    }
}

/* Emits a call sequence to the given address.
 * If the address is in range, a BL[X] to the address is generated,
 * with the bottom bit of the address being used to correctly deal
 * with interworking.
 *
 * Emits an indirect jump if the address is not in range. The exact
 * sequence of code generated in this case depends on the architecture
 * version, and may corrupt the IP register:
 *     - for v4:     MOV LR,PC; LDR PC,=addr
 *     - for v4T:    LDR IP,=addr; MOV LR,PC; BX IP  (if calling Thumb)
 *                or MOV LR,PC; LDR PC,=addr         (if calling ARM)
 *     - for v5:     LDR IP,=addr; BLX IP
 *
 * Note that on v4T, if the address is in range of BL[X], but requires
 * interworking, then the indirect jump sequence is emitted instead,
 * because v4T does not have the BLX instruction.
 *
 * Note that for v5+, it may be possible to avoid the interlock between
 * the LDR and BLX by using BL_noload() instead of BL(), and then doing
 * the load of the address into a register yourself.
 */
void
Assembler::BL(NIns* addr)
{
    if (BL_noload(addr, IP)) {
        LDi(IP, (intptr_t)addr);
    }
}


/* Emits a BL[X] to the given address if it is in range, correctly
 * dealing with interworking by using the bottom bit of the address.
 *
 * Emits an indirect jump, possibly using the given register, if the
 * address is not in range. This jump will be suitable for all
 * interworking situations. The format of the jump depends on the
 * architecture version:
 *     - for v4:     MOV LR,PC; LDR PC,=addr
 *     - for v4T:    MOV LR,PC; BX reg        [*]  (if calling Thumb)
 *                or MOV LR,PC; LDR PC,=addr       (if calling ARM)
 *     - for v5+:    BLX reg                  [*]
 * Note that reg is not allowed to be LR on v4T architectures.
 *
 * Further note: on v4T, if the address is in range of BL[X], but
 * requires interworking, then the indirect jump sequence is emitted
 * instead, because v4T does not have the BLX instruction.
 *
 * This function returns 'true' if the sequences marked [*] above are
 * generated, indicating that the caller must load the address into
 * the register themselves for this code sequence to work.
 * In all other cases, 'false' is returned, indicating the caller
 * need take no further action.
 */
bool Assembler::BL_noload(NIns* addr, Register reg)
{
    intptr_t offs;
    int bit0,bit1;

    underrunProtect(4);
    offs = PC_OFFSET_FROM(addr,_nIns-1);
    bit0 = offs & 1;
    bit1 = (offs >> 1) & 1;
    offs >>= 2;
#if NJ_ARM_ARCH <= NJ_ARM_V4
    NanoAssert(bit0 == 0);
#endif

#if NJ_ARM_ARCH == NJ_ARM_V4T
    if (isS24(offs) && bit0==0) {
#else
    if (isS24(offs)) {
#endif
#if NJ_ARM_ARCH >= NJ_ARM_V5
        if (bit0) {
            *(--_nIns) = (NIns)( 0xFA000000 | (bit1 << 24) | (offs & 0xFFFFFF) );
            asm_output("blx %p", addr);
        } else
#endif
        {
            *(--_nIns) = (NIns)( COND_AL | (0xB<<24) | (offs & 0xFFFFFF) );
            asm_output("bl %p", addr);
        }
        return false;
    } else {
#if NJ_ARM_ARCH <= NJ_ARM_V4
        (void)reg;
        underrunProtect(4 + LD32_size); // keep LDR PC and MOV LR,PC in same page
        LDi(PC,(uintptr_t)addr);
        MOV(LR,PC);
        return false;
#elif NJ_ARM_ARCH == NJ_ARM_V4T
        NanoAssert(reg != LR);
        NanoAssert(reg != PC);
        if (bit0==1) {
            underrunProtect(8); // keep BX and MOV LR,PC in same page
            BX(reg);
            MOV(LR,PC);
            return true;
        } else {
            underrunProtect(4 + LD32_size); // keep LDR PC and MOV LR,PC in same page
            LDi(PC,(uintptr_t)addr);
            MOV(LR,PC);
            return false;
        }
#else // v5+
        NanoAssert(reg != PC);
        if (blx_lr_bug) {
            // workaround for msft device emulator bug (blx lr emulated as no-op)
            underrunProtect(8);
            BLX(IP);
            MOV(IP,LR);
            return true;
        }
        BLX(reg);
        return true;
#endif
    }
}


void
Assembler::LD32_nochk(Register r, int32_t imm)
{
    // We should always reach the const pool, since it's on the same 4K code block (<4096);
    // if we can't, someone didn't underrunProtect enough.

    //fprintf (stderr, "wrote slot(2) %p with %08x, jmp @ %p\n", _nSlot, (intptr_t)imm, _nIns-1);

    int offset = PC_OFFSET_FROM(_nSlot,_nIns-1);
    NanoAssert(offset > -0x1008);
    while (offset <= -0x1000) {
        // _nSlot and _nIns are in the same 4k range but pc is 8 bytes ahead of _nIns, so
        // _nSlot may not be in "pc load range" (4k): (assume offsets relative to this->codeStart)
        // If _nSlot is at +0, and _nIns is at +0xFFC, then PC is at +0x1004,
        // so offset is -0x1004, which is just over the 4K allowed range.
        // We simply increment _nSlot to come within range and waste a small amount of
        // constant pool space.
        _nSlot++;
        offset += 4;
    }

    NanoAssert(isS12(offset) && (offset < 0));
    *(_nSlot++) = (int)imm;
    asm_output("  (%d(PC) = 0x%x)", offset, imm);
    LDR_nochk(r,PC,offset);
    NanoAssert(uintptr_t(_nIns) + 8 + offset == uintptr_t(_nSlot-1));
    NanoAssert(*((int32_t*)_nSlot-1) == imm);
}

void
Assembler::asm_ldr_chk(Register d, Register b, int32_t off, bool chk)
{
#ifdef NJ_ARM_VFP
    if (IsFpReg(d)) {
        FLDD_chk(d, b, off, chk);
    } else
#endif
    if (off < 0) {
        if (chk) underrunProtect(4);
        NanoAssert(off > -4096);
        *(--_nIns) = NIns(COND_AL | (0x51<<20) | (b<<16) | (d<<12) | ((-off) & 0xFFF));
        asm_output("ldr %s, [%s, #-%d]", gpn(d), gpn(b), -off);
    } else {
        if (isS16(off) || isU16(off)) {
            if (chk) underrunProtect(4);
            NanoAssert(off < 4096);
            *(--_nIns) = NIns(COND_AL | (0x59<<20) | (b<<16) | (d<<12) | (off & 0xFFF));
            asm_output("ldr %s, [%s, #%d]", gpn(d), gpn(b), off);
        } else {
            if (chk) underrunProtect(4 + LD32_size);
            *(--_nIns) = NIns(COND_AL | (0x79<<20) | (b<<16) | (d<<12) | IP);
            LD32_nochk(IP, off);
        }
    }
}

void
Assembler::asm_ld_imm(Register d, int32_t imm)
{
    NanoAssert(IsGpReg(d));
    if (isU8(imm)) {
        underrunProtect(4);
        // MOV d, #imm
        *(--_nIns) = (NIns)( COND_AL | 0x3B<<20 | d<<12 | imm);
        asm_output("mov %s,0x%x",gpn(d), imm);
    } else if (isU8(~imm)) {
        underrunProtect(4);
        // MVN d, #imm
        *(--_nIns) = (NIns)( COND_AL | 0x3E<<20 | d<<12 | ~imm);
        asm_output("mvn %s,0x%x",gpn(d), ~imm);
    } else {
        underrunProtect(LD32_size);
        LD32_nochk(d, imm);
    }
}

// Branch to target address _t with condition _c, doing underrun
// checks (_chk == 1) or skipping them (_chk == 0).
//
// Set the target address (_t) to 0 if the target is not yet known and the
// branch will be patched up later.
//
// If the jump is to a known address (i.e. _t != 0), and it fits in a
// relative jump (+/-32MB), emit that.
// If the jump is unconditional, emit the dest address inline in
// the instruction stream and load it into pc.
// If the jump has a condition, but noone's mucked with _nIns and our _nSlot
// pointer is valid, stick the constant in the slot and emit a conditional
// load into pc.
// Otherwise, emit the conditional load into pc from a nearby constant,
// and emit a jump to jump over it it in case the condition fails.
//
// NB: B_nochk depends on this not calling samepage() when _c == AL
void
Assembler::B_cond_chk(ConditionCode _c, NIns* _t, bool _chk)
{
    int32_t offs = PC_OFFSET_FROM(_t,_nIns-1);
    //fprintf(stderr, "B_cond_chk target: 0x%08x offset: %d @0x%08x\n", _t, offs, _nIns-1);
    if ((isS24(offs>>2)) && (_t != 0)) {
        if (_chk) {
            underrunProtect(4);
            offs = PC_OFFSET_FROM(_t,_nIns-1);
        }
    }

    if ((isS24(offs>>2)) && (_t != 0)) {
        *(--_nIns) = (NIns)( ((_c)<<28) | (0xA<<24) | (((offs)>>2) & 0xFFFFFF) );
        asm_output("b%s %p", _c == AL ? "" : condNames[_c], (void*)(_t));
    } else if (_c == AL) {
        if(_chk) underrunProtect(8);
        *(--_nIns) = (NIns)(_t);
        *(--_nIns) = (NIns)( COND_AL | (0x51<<20) | (PC<<16) | (PC<<12) | 0x4 );
        asm_output("b%s %p", _c == AL ? "" : condNames[_c], (void*)(_t));
    } else if (PC_OFFSET_FROM(_nSlot, _nIns-1) > -0x1000) {
        if(_chk) underrunProtect(8);
        *(_nSlot++) = (NIns)(_t);
        offs = PC_OFFSET_FROM(_nSlot-1,_nIns-1);
        NanoAssert(offs < 0);
        *(--_nIns) = (NIns)( ((_c)<<28) | (0x51<<20) | (PC<<16) | (PC<<12) | ((-offs) & 0xFFF) );
        asm_output("ldr%s %s, [%s, #-%d]", condNames[_c], gpn(PC), gpn(PC), -offs);
        NanoAssert(uintptr_t(_nIns)+8+offs == uintptr_t(_nSlot-1));
    } else {
        if(_chk) underrunProtect(12);
        *(--_nIns) = (NIns)(_t);
        *(--_nIns) = (NIns)( COND_AL | (0xA<<24) | ((0>>2) & 0xFFFFFF) );
        *(--_nIns) = (NIns)( ((_c)<<28) | (0x51<<20) | (PC<<16) | (PC<<12) | 0x0 );
        asm_output("b%s %p", _c == AL ? "" : condNames[_c], (void*)(_t));
    }
}

void
Assembler::asm_add_imm(Register rd, Register rn, int32_t imm, int stat)
{
    int rot = 16;
    uint32_t immval;
    bool pos;

    if (imm >= 0) {
        immval = (uint32_t) imm;
        pos = true;
    } else {
        immval = (uint32_t) (-imm);
        pos = false;
    }

    while (immval > 255 &&
           immval && ((immval & 0x3) == 0))
    {
        immval >>= 2;
        rot--;
    }

    rot &= 0xf;

    underrunProtect(4 + LD32_size);
    if (immval < 256) {
        if (pos) {
            ALUi_rot(AL, add, stat, rd, rn, immval, rot);
        } else {
            ALUi_rot(AL, sub, stat, rd, rn, immval, rot);
        }
   } else {
        // add scratch to rn, after loading the value into scratch.
        // make sure someone isn't trying to use IP as an operand
        NanoAssert(rn != IP);
        ALUr(AL, add, stat, rd, rn, IP);
        asm_ld_imm(IP, imm);
    }
}

void
Assembler::asm_sub_imm(Register rd, Register rn, int32_t imm, int stat)
{
    if (imm > -256 && imm < 256) {
        underrunProtect(4);
        if (imm >= 0)
            ALUi(AL, sub, stat, rd, rn, imm);
        else
            ALUi(AL, add, stat, rd, rn, -imm);
    } else if (imm >= 0) {
        if (imm <= 510) {
            /* between 0 and 510, inclusive */
            int rem = imm - 255;
            NanoAssert(rem < 256);
            ALUi(AL, sub, stat, rd, rn, rem & 0xff);
            ALUi(AL, sub, stat, rd, rn, 0xff);
        } else {
            /* more than 510 */
            NanoAssert(rn != IP);
            underrunProtect(4 + LD32_size);
            ALUr(AL, sub, stat, rd, rn, IP);
            asm_ld_imm(IP, imm);
        }
    } else {
        if (imm >= -510) {
            /* between -510 and -1, inclusive */
            int rem = -imm - 255;
            ALUi(AL, add, stat, rd, rn, rem & 0xff);
            ALUi(AL, add, stat, rd, rn, 0xff);
        } else {
            /* less than -510 */
            NanoAssert(rn != IP);
            underrunProtect(4 + LD32_size);
            ALUr(AL, add, stat, rd, rn, IP);
            asm_ld_imm(IP, -imm);
        }
    }
}

#ifdef NJ_ARM_VFP

void
Assembler::asm_i2f(LInsp ins)
{
    Register rr = prepResultReg(ins, FpRegs);
    Register srcr = findRegFor(ins->oprnd1(), GpRegs);

    // todo: support int value in memory, as per x86
    NanoAssert(srcr != UnknownReg);

    FSITOD(rr, FpSingleScratch);
    FMSR(FpSingleScratch, srcr);
}

void
Assembler::asm_u2f(LInsp ins)
{
    Register rr = prepResultReg(ins, FpRegs);
    Register sr = findRegFor(ins->oprnd1(), GpRegs);

    // todo: support int value in memory, as per x86
    NanoAssert(sr != UnknownReg);

    FUITOD(rr, FpSingleScratch);
    FMSR(FpSingleScratch, sr);
}

void
Assembler::asm_fneg(LInsp ins)
{
    LInsp lhs = ins->oprnd1();
    Register rr = prepResultReg(ins, FpRegs);

    Reservation* rA = getresv(lhs);
    Register sr;

    if (!rA || rA->reg == UnknownReg)
        sr = findRegFor(lhs, FpRegs);
    else
        sr = rA->reg;

    FNEGD(rr, sr);
}

void
Assembler::asm_fop(LInsp ins)
{
    LInsp lhs = ins->oprnd1();
    LInsp rhs = ins->oprnd2();
    LOpcode op = ins->opcode();

    NanoAssert(op >= LIR_fadd && op <= LIR_fdiv);

    // rr = ra OP rb

    Register rr = prepResultReg(ins, FpRegs);

    Register ra = findRegFor(lhs, FpRegs);
    Register rb = (rhs == lhs) ? ra : findRegFor(rhs, FpRegs & ~rmask(ra));

    // XXX special-case 1.0 and 0.0

    switch (op)
    {
        case LIR_fadd:      FADDD(rr,ra,rb);    break;
        case LIR_fsub:      FSUBD(rr,ra,rb);    break;
        case LIR_fmul:      FMULD(rr,ra,rb);    break;
        case LIR_fdiv:      FDIVD(rr,ra,rb);    break;
        default:            NanoAssert(0);      break;
    }
}

void
Assembler::asm_fcmp(LInsp ins)
{
    LInsp lhs = ins->oprnd1();
    LInsp rhs = ins->oprnd2();
    LOpcode op = ins->opcode();
    NanoAssert(op >= LIR_feq && op <= LIR_fge);

    Reservation *rA, *rB;
    findRegFor2(FpRegs, lhs, rA, rhs, rB);
    Register ra = rA->reg;
    Register rb = rB->reg;

    int e_bit = (op != LIR_feq);

    // do the comparison and get results loaded in ARM status register
    FMSTAT();
    FCMPD(ra, rb, e_bit);
}

Register
Assembler::asm_prep_fcall(Reservation*, LInsp)
{
    /* Because ARM actually returns the result in (R0,R1), and not in a
     * floating point register, the code to move the result into a correct
     * register is at the beginning of asm_call(). This function does
     * nothing.
     *
     * The reason being that if this function did something, the final code
     * sequence we'd get would be something like:
     *     MOV {R0-R3},params        [from asm_call()]
     *     BL function               [from asm_call()]
     *     MOV {R0-R3},spilled data  [from evictScratchRegs()]
     *     MOV Dx,{R0,R1}            [from this function]
     * which is clearly broken.
     *
     * This is not a problem for non-floating point calls, because the
     * restoring of spilled data into R0 is done via a call to prepResultReg(R0)
     * at the same point in the sequence as this function is called, meaning that
     * evictScratchRegs() will not modify R0. However, prepResultReg is not aware
     * of the concept of using a register pair (R0,R1) for the result of a single
     * operation, so it can only be used here with the ultimate VFP register, and
     * not R0/R1, which potentially allows for R0/R1 to get corrupted as described.
     */
    return UnknownReg;
}
#endif

    /* Call this with targ set to 0 if the target is not yet known and the branch
     * will be patched up later.
     */
    NIns* Assembler::asm_branch(bool branchOnFalse, LInsp cond, NIns* targ)
    {
        NIns* at = 0;
        LOpcode condop = cond->opcode();
        NanoAssert(cond->isCond());

        ConditionCode arm_cond;
#ifdef NJ_SOFTFLOAT
        NanoAssert((condop < LIR_feq) || (condop > LIR_fge));
#endif

        switch (condop) {
#ifdef NJ_ARM_VFP
            case LIR_feq: arm_cond=EQ; break;
            case LIR_flt: arm_cond=LO; break; // } note: VFP LT/LE operations require use of
            case LIR_fle: arm_cond=LS; break; // } unsigned LO/LS condition codes!
            case LIR_fge: arm_cond=GE; break;
            case LIR_fgt: arm_cond=GT; break;
#endif
            case LIR_eq:  arm_cond=EQ; break;
            case LIR_ov:  arm_cond=VS; break;
            case LIR_lt:  arm_cond=LT; break;
            case LIR_le:  arm_cond=LE; break;
            case LIR_gt:  arm_cond=GT; break;
            case LIR_ge:  arm_cond=GE; break;
            case LIR_ult: arm_cond=LO; break;
            case LIR_ule: arm_cond=LS; break;
            case LIR_ugt: arm_cond=HI; break;
            default: /*LIR_uge*/ arm_cond=HS; break;  // use default to avoid compiler warning
        }

        if (branchOnFalse) arm_cond = OppositeCond(arm_cond);

        B_cond(arm_cond, targ);

        at = _nIns;
#ifdef NJ_ARM_VFP
        if ((condop >= LIR_feq) && (condop <= LIR_fge))
            asm_fcmp(cond);
        else
            asm_cmp(cond);
#else
        asm_cmp(cond);
#endif
        return at;
    }

    void
    Assembler::asm_cmp(LIns *cond)
    {
        LOpcode condop = cond->opcode();

        // LIR_ov recycles the flags set by arithmetic ops
        if ((condop == LIR_ov))
            return;

        LInsp lhs = cond->oprnd1();
        LInsp rhs = cond->oprnd2();
        Reservation *rA, *rB;

        // Not supported yet.
        NanoAssert(!lhs->isQuad() && !rhs->isQuad());

        // ready to issue the compare
        if (rhs->isconst()) {
            int c = rhs->imm32();
            if (c == 0 && cond->isop(LIR_eq)) {
                Register r = findRegFor(lhs, GpRegs);
                TST(r,r);
                // No 64-bit immediates so fall-back to below
            } else if (!rhs->isQuad()) {
                Register r = getBaseReg(lhs, c, GpRegs);
                asm_cmpi(r, c);
            } else {
                NanoAssert(0);
            }
        } else {
            findRegFor2(GpRegs, lhs, rA, rhs, rB);
            Register ra = rA->reg;
            Register rb = rB->reg;
            CMP(ra, rb);
        }
    }

    void
    Assembler::asm_cmpi(Register r, int32_t imm)
    {
        if (imm < 0) {
            if (imm > -256) {
                ALUi(AL, cmn, 1, 0, r, -imm);
            } else {
                underrunProtect(4 + LD32_size);
                CMP(r, IP);
                asm_ld_imm(IP, imm);
            }
        } else {
            if (imm < 256) {
                ALUi(AL, cmp, 1, 0, r, imm);
            } else {
                underrunProtect(4 + LD32_size);
                CMP(r, IP);
                asm_ld_imm(IP, imm);
            }
        }
    }

void
Assembler::asm_loop(LInsp ins, NInsList& loopJumps)
{
    // XXX asm_loop should be in Assembler.cpp!

    B_long_placeholder(); // jump to SOT
    loopJumps.add(_nIns);

    // If the target we are looping to is in a different fragment, we have to restore
    // SP since we will target fragEntry and not loopEntry.
    if (ins->record()->exit->target != _thisfrag)
        MOV(SP,FP);
}

#ifdef NJ_ARM_VFP
    void
    Assembler::asm_fcond(LInsp ins)
    {
        // only want certain regs
        Register r = prepResultReg(ins, AllowableFlagRegs);

        switch (ins->opcode()) {
            case LIR_feq: SETEQ(r); break;
            case LIR_flt: SETLO(r); break; // } note: VFP LT/LE operations require use of
            case LIR_fle: SETLS(r); break; // } unsigned LO/LS condition codes!
            case LIR_fge: SETGE(r); break;
            case LIR_fgt: SETGT(r); break;
            default: NanoAssert(0); break;
        }
        asm_fcmp(ins);
    }
#endif

    void
    Assembler::asm_cond(LInsp ins)
    {
        Register r = prepResultReg(ins, AllowableFlagRegs);
        switch(ins->opcode())
        {
            case LIR_eq:  SETEQ(r); break;
            case LIR_ov:  SETVS(r); break;
            case LIR_lt:  SETLT(r); break;
            case LIR_le:  SETLE(r); break;
            case LIR_gt:  SETGT(r); break;
            case LIR_ge:  SETGE(r); break;
            case LIR_ult: SETLO(r); break;
            case LIR_ule: SETLS(r); break;
            case LIR_ugt: SETHI(r); break;
            case LIR_uge: SETHS(r); break;
            default:        NanoAssert(0);  break;
        }
        asm_cmp(ins);
    }

    void
    Assembler::asm_arith(LInsp ins)
    {
        LOpcode op = ins->opcode();
        LInsp lhs = ins->oprnd1();
        LInsp rhs = ins->oprnd2();

        Register rb = UnknownReg;
        RegisterMask allow = GpRegs;
        bool forceReg = (op == LIR_mul || !rhs->isconst());

        // Arm can't do an immediate op with immediates
        // outside of +/-255 (for AND) r outside of
        // 0..255 for others.
        if (!forceReg) {
            if ((op != LIR_lsh) && (op != LIR_rsh) && (LIR_ush) &&
                rhs->isconst() && !isU8(rhs->imm32()))
                forceReg = true;
        }

        if (lhs != rhs && forceReg) {
            if ((rb = asm_binop_rhs_reg(ins)) == UnknownReg) {
                rb = findRegFor(rhs, allow);
            }
            allow &= ~rmask(rb);
        } else if ((op == LIR_add||op == LIR_addp) && lhs->isop(LIR_alloc) && rhs->isconst()) {
            // add alloc+const, rr wants the address of the allocated space plus a constant
            Register rr = prepResultReg(ins, allow);
            int d = findMemFor(lhs) + rhs->imm32();
            asm_add_imm(rr, FP, d);
        }

        Register rr = prepResultReg(ins, allow);
        Reservation* rA = getresv(lhs);
        Register ra;
        // if this is last use of lhs in reg, we can re-use result reg
        if (rA == 0 || (ra = rA->reg) == UnknownReg)
            ra = findSpecificRegFor(lhs, rr);
        // else, rA already has a register assigned.
        NanoAssert(ra != UnknownReg);

        if (forceReg) {
            if (lhs == rhs)
                rb = ra;

            if (op == LIR_add || op == LIR_addp)
                ADDs(rr, ra, rb, 1);
            else if (op == LIR_sub)
                SUB(rr, ra, rb);
            else if (op == LIR_mul)
#if NJ_ARM_ARCH >= NJ_ARM_V6
                MUL(rr, ra, rb);
#else
                if (rr == ra) {
                    MUL(rr, IP, rb);
                    MOV(IP, ra);
                } else {
                MUL(rr, ra, rb);
                }
#endif
            else if (op == LIR_and)
                AND(rr, ra, rb);
            else if (op == LIR_or)
                ORR(rr, ra, rb);
            else if (op == LIR_xor)
                EOR(rr, ra, rb);
            else if (op == LIR_lsh) {
                LSL(rr, ra, IP);
                ANDi(IP, rb, 31);
            } else if (op == LIR_rsh) {
                ASR(rr, ra, IP);
                ANDi(IP, rb, 31);
            } else if (op == LIR_ush) {
                LSR(rr, ra, IP);
                ANDi(IP, rb, 31);
            } else
                NanoAssertMsg(0, "Unsupported");
        } else {
            int c = rhs->imm32();
            if (op == LIR_add || op == LIR_addp) {
                asm_add_imm(rr, ra, c, 0);
            } else if (op == LIR_sub) {
                asm_sub_imm(rr, ra, c);
            } else if (op == LIR_and) {
                if (isU8(c)) {
                    ANDi(rr, ra, c);
                } else if (c < 0 && c > -256) {
                    AND(rr, ra, IP);
                    ALUi(AL, mvn, 0, IP, 0, (~c)&255);
                } else {
                    NanoAssert(0);
                }
            } else if (op == LIR_or)
                ORRi(rr, ra, c);
            else if (op == LIR_xor)
                EORi(rr, ra, c);
            else if (op == LIR_lsh)
                LSLi(rr, ra, c & 31);
            else if (op == LIR_rsh)
                ASRi(rr, ra, c & 31);
            else if (op == LIR_ush)
                LSRi(rr, ra, c & 31);
            else
                NanoAssertMsg(0, "Unsupported");
        }
    }

    void
    Assembler::asm_neg_not(LInsp ins)
    {
        LOpcode op = ins->opcode();
        Register rr = prepResultReg(ins, GpRegs);

        LIns* lhs = ins->oprnd1();
        Reservation *rA = getresv(lhs);
        // if this is last use of lhs in reg, we can re-use result reg
        Register ra;
        if (rA == 0 || (ra=rA->reg) == UnknownReg)
            ra = findSpecificRegFor(lhs, rr);
        // else, rA already has a register assigned.
        NanoAssert(ra != UnknownReg);

        if (op == LIR_not)
            MVN(rr, ra);
        else
            RSBS(rr, ra);
    }

    void
    Assembler::asm_ld(LInsp ins)
    {
        LOpcode op = ins->opcode();
        LIns* base = ins->oprnd1();
        int d = ins->disp();

        Register rr = prepResultReg(ins, GpRegs);
        Register ra = getBaseReg(base, d, GpRegs);

        // these will always be 4-byte aligned
        if (op == LIR_ld || op == LIR_ldc) {
            LDR(rr, ra, d);
            return;
        }

        // these will be 2 or 4-byte aligned
        if (op == LIR_ldcs) {
            LDRH(rr, ra, d);
            return;
        }

        // aaand this is just any byte.
        if (op == LIR_ldcb) {
            LDRB(rr, ra, d);
            return;
        }

        NanoAssertMsg(0, "Unsupported instruction in asm_ld");
    }

    void
    Assembler::asm_cmov(LInsp ins)
    {
        NanoAssert(ins->opcode() == LIR_cmov);
        LIns* condval = ins->oprnd1();
        LIns* iftrue  = ins->oprnd2();
        LIns* iffalse = ins->oprnd3();

        NanoAssert(condval->isCmp());
        NanoAssert(!iftrue->isQuad() && !iffalse->isQuad());

        const Register rr = prepResultReg(ins, GpRegs);

        // this code assumes that neither LD nor MR nor MRcc set any of the condition flags.
        // (This is true on Intel, is it true on all architectures?)
        const Register iffalsereg = findRegFor(iffalse, GpRegs & ~rmask(rr));
        switch (condval->opcode())
        {
            // note that these are all opposites...
            case LIR_eq:    MOVNE(rr, iffalsereg);  break;
            case LIR_ov:    MOVVC(rr, iffalsereg);   break;
            case LIR_lt:    MOVGE(rr, iffalsereg);  break;
            case LIR_le:    MOVGT(rr, iffalsereg);  break;
            case LIR_gt:    MOVLE(rr, iffalsereg);  break;
            case LIR_ge:    MOVLT(rr, iffalsereg);  break;
            case LIR_ult:   MOVHS(rr, iffalsereg);  break;
            case LIR_ule:   MOVHI(rr, iffalsereg);  break;
            case LIR_ugt:   MOVLS(rr, iffalsereg);  break;
            case LIR_uge:   MOVLO(rr, iffalsereg);  break;
            debug_only( default: NanoAssert(0); break; )
        }
        /*const Register iftruereg =*/ findSpecificRegFor(iftrue, rr);
        asm_cmp(condval);
    }

    void
    Assembler::asm_qhi(LInsp ins)
    {
        Register rr = prepResultReg(ins, GpRegs);
        LIns *q = ins->oprnd1();
        int d = findMemFor(q);
        LDR(rr, FP, d+4);
    }

    void
    Assembler::asm_qlo(LInsp ins)
    {
        Register rr = prepResultReg(ins, GpRegs);
        LIns *q = ins->oprnd1();
        int d = findMemFor(q);
        LDR(rr, FP, d);
    }

    void
    Assembler::asm_param(LInsp ins)
    {
        uint32_t a = ins->paramArg();
        uint32_t kind = ins->paramKind();
        if (kind == 0) {
            // ordinary param
            AbiKind abi = _thisfrag->lirbuf->abi;
            uint32_t abi_regcount = abi == ABI_CDECL ? 4 : abi == ABI_FASTCALL ? 2 : abi == ABI_THISCALL ? 1 : 0;
            if (a < abi_regcount) {
                // incoming arg in register
                prepResultReg(ins, rmask(argRegs[a]));
            } else {
                // incoming arg is on stack, and EBP points nearby (see genPrologue)
                Register r = prepResultReg(ins, GpRegs);
                int d = (a - abi_regcount) * sizeof(intptr_t) + 8;
                LD(r, d, FP);
            }
        } else {
            // saved param
            prepResultReg(ins, rmask(savedRegs[a]));
        }
    }

void
Assembler::asm_int(LInsp ins)
{
    Register rr = prepResultReg(ins, GpRegs);
    int32_t val = ins->imm32();
    if (val == 0)
        EOR(rr,rr,rr);
    else
        LDi(rr, val);
}

void
Assembler::asm_ret(LIns *ins)
{
    if (_nIns != _epilogue) {
        B(_epilogue);
    }
    assignSavedRegs();
    LIns *value = ins->oprnd1();
    if (ins->isop(LIR_ret)) {
        findSpecificRegFor(value, R0);
    }
    else {
        NanoAssert(ins->isop(LIR_fret));
#ifdef NJ_ARM_VFP
        Register reg = findRegFor(value, FpRegs);
        FMRRD(R0, R1, reg);
#else
        NanoAssert(value->isop(LIR_qjoin));
        findSpecificRegFor(value->oprnd1(), R0); // lo
        findSpecificRegFor(value->oprnd2(), R1); // hi
#endif
    }
}

void
Assembler::asm_promote(LIns *ins)
{
    /* The LIR opcodes that result in a call to asm_promote are only generated
     * if NANOJIT_64BIT is #define'd, which it never is for ARM.
     */
    (void)ins;
    NanoAssert(0);
}

}
#endif /* FEATURE_NANOJIT */
