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

#ifdef UNDER_CE
#include <cmnintrin.h>
extern "C" bool blx_lr_broken();
#endif

#if defined(FEATURE_NANOJIT) && defined(NANOJIT_ARM)

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

// NB the thumb2 check (i.e using > v6) is technically 
// not correct, but its close enough for now).
#ifdef JS_TRACER
#   define IS_ARM_ARCH_GT_V5()    (AvmCore::config.arch > 5)
#   define IS_ARM_ARCH_VFP()      (AvmCore::config.vfp)
#   define IS_ARM_ARCH_THUMB2()   (AvmCore::config.thumb2)
#else 
#   if NJ_ARM_ARCH > NJ_ARM_V5
#      define IS_ARM_ARCH_GT_V5() (1)
#   else
#      define IS_ARM_ARCH_GT_V5() (0)
#   endif
#   if NJ_ARM_ARCH > NJ_ARM_V6
#      define IS_ARM_ARCH_THUMB2() (1)
#   else
#      define IS_ARM_ARCH_THUMB2() (0)
#   endif
#   ifdef NJ_ARM_VFP
#      define IS_ARM_ARCH_VFP()   (1)
#   else
#      define IS_ARM_ARCH_VFP()   (0)
#   endif
#endif // JS_TRACER

#ifdef DEBUG
// Return true if enc is a valid Operand 2 encoding and thus can be used as-is
// in an ARM arithmetic operation that accepts such encoding.
//
// This utility does not know (or determine) the actual value that the encoded
// value represents, and thus cannot be used to ensure the correct operation of
// encOp2Imm, but it does ensure that the encoded value can be used to encode a
// valid ARM instruction. decOp2Imm can be used if you also need to check that
// a literal is correctly encoded (and thus that encOp2Imm is working
// correctly).
inline bool
Assembler::isOp2Imm(uint32_t enc)
{
    return ((enc & 0xfff) == enc);
}

// Decodes operand 2 immediate values (for debug output and assertions).
inline uint32_t
Assembler::decOp2Imm(uint32_t enc)
{
    NanoAssert(isOp2Imm(enc));

    uint32_t    imm8 = enc & 0xff;
    uint32_t    rot = 32 - ((enc >> 7) & 0x1e);

    return imm8 << (rot & 0x1f);
}
#endif

// Calculate the number of leading zeroes in data.
inline uint32_t
Assembler::CountLeadingZeroes(uint32_t data)
{
    uint32_t    leading_zeroes;

    // We can't do CLZ on anything earlier than ARMv5. Architectures as early
    // as that aren't supported, but assert that we aren't running on one
    // anyway.
    // If ARMv4 support is required in the future for some reason, we can do a
    // run-time check on config.arch and fall back to the C routine, but for
    // now we can avoid the cost of the check as we don't intend to support
    // ARMv4 anyway.
#ifdef TM_MERGE    
    NanoAssert(IS_ARM_ARCH_GT_V5());
#endif

#if defined(__ARMCC__)
    // ARMCC can do this with an intrinsic.
    leading_zeroes = __clz(data);

// current Android GCC compiler incorrectly refuses to compile 'clz' for armv5
// (even though this is a legal instruction there). Since we currently only compile for ARMv5
// for emulation, we don't care too much (but we DO care for ARMv6+ since those are "real"
// devices).
#elif defined(__GNUC__) && !(defined(ANDROID) && __ARM_ARCH__ <= 5) 
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

    // Assert that the operation worked!
    NanoAssert(((0xffffffff >> leading_zeroes) & data) == data);

    return leading_zeroes;
}

// The ARM instruction set allows some flexibility to the second operand of
// most arithmetic operations. When operand 2 is an immediate value, it takes
// the form of an 8-bit value rotated by an even value in the range 0-30.
//
// Some values that can be encoded this scheme — such as 0xf000000f — are
// probably fairly rare in practice and require extra code to detect, so this
// function implements a fast CLZ-based heuristic to detect any value that can
// be encoded using just a shift, and not a full rotation. For example,
// 0xff000000 and 0x000000ff are both detected, but 0xf000000f is not.
//
// This function will return true to indicate that the encoding was successful,
// or false to indicate that the literal could not be encoded as an operand 2
// immediate. If successful, the encoded value will be written to *enc.
inline bool
Assembler::encOp2Imm(uint32_t literal, uint32_t * enc)
{
    // The number of leading zeroes in the literal. This is used to calculate
    // the rotation component of the encoding.
    uint32_t    leading_zeroes;

    // Components of the operand 2 encoding.
    int32_t     rot;
    uint32_t    imm8;

    // Check the literal to see if it is a simple 8-bit value. I suspect that
    // most literals are in fact small values, so doing this check early should
    // give a decent speed-up.
    if (literal < 256)
    {
        *enc = literal;
        return true;
    }

    // Determine the number of leading zeroes in the literal. This is used to
    // calculate the required rotation.
    leading_zeroes = CountLeadingZeroes(literal);

    // We've already done a check to see if the literal is an 8-bit value, so
    // leading_zeroes must be less than (and not equal to) (32-8)=24. However,
    // if it is greater than 24, this algorithm will break, so debug code
    // should use an assertion here to check that we have a value that we
    // expect.
    NanoAssert(leading_zeroes < 24);

    // Assuming that we have a field of no more than 8 bits for a valid
    // literal, we can calculate the required rotation by subtracting
    // leading_zeroes from (32-8):
    //
    // Example:
    //      0: Known to be zero.
    //      1: Known to be one.
    //      X: Either zero or one.
    //      .: Zero in a valid operand 2 literal.
    //
    //  Literal:     [ 1XXXXXXX ........ ........ ........ ]
    //  leading_zeroes = 0
    //  Therefore rot (left) = 24.
    //  Encoded 8-bit literal:                  [ 1XXXXXXX ]
    //
    //  Literal:     [ ........ ..1XXXXX XX...... ........ ]
    //  leading_zeroes = 10
    //  Therefore rot (left) = 14.
    //  Encoded 8-bit literal:                  [ 1XXXXXXX ]
    //
    // Note, however, that we can only encode even shifts, and so
    // "rot=24-leading_zeroes" is not sufficient by itself. By ignoring
    // zero-bits in odd bit positions, we can ensure that we get a valid
    // encoding.
    //
    // Example:
    //  Literal:     [ 01XXXXXX ........ ........ ........ ]
    //  leading_zeroes = 1
    //  Therefore rot (left) = round_up(23) = 24.
    //  Encoded 8-bit literal:                  [ 01XXXXXX ]
    rot = 24 - (leading_zeroes & ~1);

    // The imm8 component of the operand 2 encoding can be calculated from the
    // rot value.
    imm8 = literal >> rot;

    // The validity of the literal can be checked by reversing the
    // calculation. It is much easier to decode the immediate than it is to
    // encode it!
    if (literal != (imm8 << rot)) {
        // The encoding is not valid, so report the failure. Calling code
        // should use some other method of loading the value (such as LDR).
        return false;
    }

    // The operand is valid, so encode it.
    // Note that the ARM encoding is actually described by a rotate to the
    // _right_, so rot must be negated here. Calculating a left shift (rather
    // than calculating a right rotation) simplifies the above code.
    *enc = ((-rot << 7) & 0xf00) | imm8;

    // Assert that the operand was properly encoded.
    NanoAssert(decOp2Imm(*enc) == literal);

    return true;
}

// Encode "rd = rn + imm" using an appropriate instruction sequence.
// Set stat to 1 to update the status flags. Otherwise, set it to 0 or omit it.
// (The declaration in NativeARM.h defines the default value of stat as 0.)
//
// It is not valid to call this function if:
//   (rd == IP) AND (rn == IP) AND !encOp2Imm(imm) AND !encOp2Imm(-imm)
// Where: if (encOp2Imm(imm)), imm can be encoded as an ARM operand 2 using the
// encOp2Imm method.
void
Assembler::asm_add_imm(Register rd, Register rn, int32_t imm, int stat /* =0 */)
{
    // Operand 2 encoding of the immediate.
    uint32_t    op2imm;

    NanoAssert(IsGpReg(rd));
    NanoAssert(IsGpReg(rn));
    NanoAssert((stat & 1) == stat);

    // Try to encode the value directly as an operand 2 immediate value, then
    // fall back to loading the value into a register.
    if (encOp2Imm(imm, &op2imm)) {
        ADDis(rd, rn, op2imm, stat);
    } else if (encOp2Imm(-imm, &op2imm)) {
        // We could not encode the value for ADD, so try to encode it for SUB.
        // Note that this is valid even if stat is set, _unless_ imm is 0, but
        // that case is caught above.
        NanoAssert(imm != 0);
        SUBis(rd, rn, op2imm, stat);
    } else {
        // We couldn't encode the value directly, so use an intermediate
        // register to encode the value. We will use IP to do this unless rn is
        // IP; in that case we can reuse rd. This allows every case other than
        // "ADD IP, IP, =#imm".
        Register    rm = (rn == IP) ? (rd) : (IP);
        NanoAssert(rn != rm);

        ADDs(rd, rn, rm, stat);
        asm_ld_imm(rm, imm);
    }
}

// Encode "rd = rn - imm" using an appropriate instruction sequence.
// Set stat to 1 to update the status flags. Otherwise, set it to 0 or omit it.
// (The declaration in NativeARM.h defines the default value of stat as 0.)
//
// It is not valid to call this function if:
//   (rd == IP) AND (rn == IP) AND !encOp2Imm(imm) AND !encOp2Imm(-imm)
// Where: if (encOp2Imm(imm)), imm can be encoded as an ARM operand 2 using the
// encOp2Imm method.
void
Assembler::asm_sub_imm(Register rd, Register rn, int32_t imm, int stat /* =0 */)
{
    // Operand 2 encoding of the immediate.
    uint32_t    op2imm;

    NanoAssert(IsGpReg(rd));
    NanoAssert(IsGpReg(rn));
    NanoAssert((stat & 1) == stat);

    // Try to encode the value directly as an operand 2 immediate value, then
    // fall back to loading the value into a register.
    if (encOp2Imm(imm, &op2imm)) {
        SUBis(rd, rn, op2imm, stat);
    } else if (encOp2Imm(-imm, &op2imm)) {
        // We could not encode the value for SUB, so try to encode it for ADD.
        // Note that this is valid even if stat is set, _unless_ imm is 0, but
        // that case is caught above.
        NanoAssert(imm != 0);
        ADDis(rd, rn, op2imm, stat);
    } else {
        // We couldn't encode the value directly, so use an intermediate
        // register to encode the value. We will use IP to do this unless rn is
        // IP; in that case we can reuse rd. This allows every case other than
        // "SUB IP, IP, =#imm".
        Register    rm = (rn == IP) ? (rd) : (IP);
        NanoAssert(rn != rm);

        SUBs(rd, rn, rm, stat);
        asm_ld_imm(rm, imm);
    }
}

// Encode "rd = rn & imm" using an appropriate instruction sequence.
// Set stat to 1 to update the status flags. Otherwise, set it to 0 or omit it.
// (The declaration in NativeARM.h defines the default value of stat as 0.)
//
// It is not valid to call this function if:
//   (rd == IP) AND (rn == IP) AND !encOp2Imm(imm) AND !encOp2Imm(~imm)
// Where: if (encOp2Imm(imm)), imm can be encoded as an ARM operand 2 using the
// encOp2Imm method.
void
Assembler::asm_and_imm(Register rd, Register rn, int32_t imm, int stat /* =0 */)
{
    // Operand 2 encoding of the immediate.
    uint32_t    op2imm;

    NanoAssert(IsGpReg(rd));
    NanoAssert(IsGpReg(rn));
    NanoAssert((stat & 1) == stat);

    // Try to encode the value directly as an operand 2 immediate value, then
    // fall back to loading the value into a register.
    if (encOp2Imm(imm, &op2imm)) {
        ANDis(rd, rn, op2imm, stat);
    } else if (encOp2Imm(~imm, &op2imm)) {
        // Use BIC with the inverted immediate.
        BICis(rd, rn, op2imm, stat);
    } else {
        // We couldn't encode the value directly, so use an intermediate
        // register to encode the value. We will use IP to do this unless rn is
        // IP; in that case we can reuse rd. This allows every case other than
        // "AND IP, IP, =#imm".
        Register    rm = (rn == IP) ? (rd) : (IP);
        NanoAssert(rn != rm);

        ANDs(rd, rn, rm, stat);
        asm_ld_imm(rm, imm);
    }
}

// Encode "rd = rn | imm" using an appropriate instruction sequence.
// Set stat to 1 to update the status flags. Otherwise, set it to 0 or omit it.
// (The declaration in NativeARM.h defines the default value of stat as 0.)
//
// It is not valid to call this function if:
//   (rd == IP) AND (rn == IP) AND !encOp2Imm(imm)
// Where: if (encOp2Imm(imm)), imm can be encoded as an ARM operand 2 using the
// encOp2Imm method.
void
Assembler::asm_orr_imm(Register rd, Register rn, int32_t imm, int stat /* =0 */)
{
    // Operand 2 encoding of the immediate.
    uint32_t    op2imm;

    NanoAssert(IsGpReg(rd));
    NanoAssert(IsGpReg(rn));
    NanoAssert((stat & 1) == stat);

    // Try to encode the value directly as an operand 2 immediate value, then
    // fall back to loading the value into a register.
    if (encOp2Imm(imm, &op2imm)) {
        ORRis(rd, rn, op2imm, stat);
    } else {
        // We couldn't encode the value directly, so use an intermediate
        // register to encode the value. We will use IP to do this unless rn is
        // IP; in that case we can reuse rd. This allows every case other than
        // "ORR IP, IP, =#imm".
        Register    rm = (rn == IP) ? (rd) : (IP);
        NanoAssert(rn != rm);

        ORRs(rd, rn, rm, stat);
        asm_ld_imm(rm, imm);
    }
}

// Encode "rd = rn ^ imm" using an appropriate instruction sequence.
// Set stat to 1 to update the status flags. Otherwise, set it to 0 or omit it.
// (The declaration in NativeARM.h defines the default value of stat as 0.)
//
// It is not valid to call this function if:
//   (rd == IP) AND (rn == IP) AND !encOp2Imm(imm)
// Where: if (encOp2Imm(imm)), imm can be encoded as an ARM operand 2 using the
// encOp2Imm method.
void
Assembler::asm_eor_imm(Register rd, Register rn, int32_t imm, int stat /* =0 */)
{
    // Operand 2 encoding of the immediate.
    uint32_t    op2imm;

    NanoAssert(IsGpReg(rd));
    NanoAssert(IsGpReg(rn));
    NanoAssert((stat & 1) == stat);

    // Try to encode the value directly as an operand 2 immediate value, then
    // fall back to loading the value into a register.
    if (encOp2Imm(imm, &op2imm)) {
        EORis(rd, rn, op2imm, stat);
    } else {
        // We couldn't encoder the value directly, so use an intermediate
        // register to encode the value. We will use IP to do this unless rn is
        // IP; in that case we can reuse rd. This allows every case other than
        // "EOR IP, IP, =#imm".
        Register    rm = (rn == IP) ? (rd) : (IP);
        NanoAssert(rn != rm);

        EORs(rd, rn, rm, stat);
        asm_ld_imm(rm, imm);
    }
}

// --------------------------------
// Assembler functions.
// --------------------------------

void
Assembler::nInit(AvmCore*)
{
#ifdef UNDER_CE
    blx_lr_bug = blx_lr_broken();
#else
    blx_lr_bug = 0;
#endif
}

void Assembler::nBeginAssembly()
{
}

NIns*
Assembler::genPrologue()
{
    /**
     * Prologue
     */

    // NJ_RESV_OFFSET is space at the top of the stack for us
    // to use for parameter passing (8 bytes at the moment)
    uint32_t stackNeeded = max_out_args + STACK_GRANULARITY * _activation.tos;
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

        GuardRecord *gr = guard->record();

        if (!_epilogue)
            _epilogue = genEpilogue();

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
        asm_ld_imm(R2, int(gr));

        // Set the jmp pointer to the start of the sequence so that patched
        // branches can skip the LDi sequence.
        gr->jmp = _nIns;
    }

#ifdef NJ_VERBOSE
    if (_frago->core()->config.show_stats) {
        // load R1 with Fragment *fromFrag, target fragment
        // will make use of this when calling fragenter().
        int fromfrag = int((Fragment*)_thisfrag);
        asm_ld_imm(argRegs[1], fromfrag);
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

#ifdef TM_MERGE
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
            asm_ld_imm(r, p->imm32());
        } else {
            Reservation* rA = getresv(p);
            if (rA) {
                if (rA->reg == UnknownReg) {
                    // load it into the arg reg
                    int d = findMemFor(p);
                    if (p->isop(LIR_alloc)) {
                        asm_add_imm(r, FP, d);
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
                asm_add_imm(IP, FP, d);
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
#endif

#ifdef NJ_ARM_EABI
        // arm eabi puts doubles only in R0:1 or R2:3, and 64bit aligned on the stack.
        if (sz == ARGSIZE_F) {
            if (r == R1)
                r = R2;
            else if (r == R3)
                r = nextreg(r);
        }
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
    NanoAssert(set != 0);

    // The CountLeadingZeroes function will use the CLZ instruction where
    // available. In other cases, it will fall back to a (slower) C
    // implementation.
    Register r = (Register)(31-CountLeadingZeroes(set));
    _allocator.free &= ~rmask(r);

    NanoAssert(IsGpReg(r) || IsFpReg(r));
    NanoAssert((rmask(r) & set) == rmask(r));

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
        asm_add_imm(r, FP, disp(resv));
    } else if (i->isconst()) {
        if (!resv->arIndex) {
            i->resv()->clear();
        }
        asm_ld_imm(r, i->imm32());
    }
    else {
        // We can't easily load immediate values directly into FP registers, so
        // ensure that memory is allocated for the constant and load it from
        // memory.    
        int d = findMemFor(i);
#ifdef NJ_ARM_VFP
        if (IsFpReg(r)) {
            if (isS8(d >> 2)) {
                FLDD(r, FP, d);
            } else {
                FLDD(r, IP, 0);
                asm_add_imm(IP, FP, d);
            }
#if 0
    // This code tries to use a small constant load to restore the value of r.
    // However, there was a comment explaining that using this regresses
    // crypto-aes by about 50%. I do not see that behaviour; however, enabling
    // this code does cause a JavaScript failure in the first of the
    // createMandelSet tests in trace-tests. I can't explain either the
    // original performance issue or the crash that I'm seeing.
    } else if (i->isconst()) {
        // asm_ld_imm will automatically select between LDR and MOV as
        // appropriate.
        if (!resv->arIndex)
            i->resv()->clear();
        asm_ld_imm(r, i->imm32());
#endif
        } else {
            LDR(r, FP, d);
        }
#else
        LDR(r, FP, d);
#endif

        verbose_only( if (_logc->lcbits & LC_RegAlloc) {
                        outputForEOL("  <= restore %s",
                        _thisfrag->lirbuf->names->formatRef(i)); }
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
                asm_add_imm(IP, FP, d);
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
    //asm_output("<<< load64");

    NanoAssert(ins->isQuad());

    LIns* base = ins->oprnd1();
    int offset = ins->disp();

#ifdef NJ_ARM_VFP
    Register rr = prepResultReg(ins, FpRegs);
    Register rb = findRegFor(base, GpRegs);

    NanoAssert(IsFpReg(rr));

    if (!isS8(offset >> 2) || (offset&3) != 0) {
        FLDD(rr,IP,0);
        asm_add_imm(IP, rb, offset);
    } else {
        FLDD(rr,rb,offset);
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
        underrunProtect(LD32_size*2 + 8);

        // XXX use another reg, get rid of dependency
        STR(IP, rb, dr);
        asm_ld_imm(IP, value->imm64_0());
        STR(IP, rb, dr+4);
        asm_ld_imm(IP, value->imm64_1());

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
        asm_add_imm(IP, rb, dr);
    }

    // if it's a constant, make sure our baseReg/baseOffset location
    // has the right value
    if (value->isconstq()) {
        underrunProtect(4*4);
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

    freeRsrcOf(ins, false);
#ifdef NJ_ARM_VFP
    Register rr = res->reg;
    NanoAssert(d || rr != UnknownReg);

#ifdef TM_MERGE
    if (IS_ARM_ARCH_VFP() &&
        rr != UnknownReg)
#endif

    if (rr != UnknownReg) {
        if (d)
            FSTD(rr, FP, d);

        underrunProtect(4*4);
        asm_quad_nochk(rr, ins->imm64_0(), ins->imm64_1());
    } else
#endif
    {
        NanoAssert(d);
        // asm_mmq might spill a reg, so don't call it;
        // instead do the equivalent directly.
        //asm_mmq(FP, d, PC, -16);

        STR(IP, FP, d+4);
        asm_ld_imm(IP, ins->imm64_1());
        STR(IP, FP, d);
        asm_ld_imm(IP, ins->imm64_0());
    }

    //asm_output("<<< asm_quad");
}

void
Assembler::asm_nongp_copy(Register r, Register s)
{
#ifdef NJ_ARM_VFP
    if (IsFpReg(r) && IsFpReg(s)) {
        // fp->fp
        FCPYD(r, s);
    } else {
        // We can't move a double-precision FP register into a 32-bit GP
        // register, so assert that no calling code is trying to do that.
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
        NanoAssert((free & rmask(PC)) == 0);
        NanoAssert((free & rmask(LR)) == 0);
        NanoAssert((free & rmask(SP)) == 0);
        NanoAssert((free & rmask(IP)) == 0);
        NanoAssert((free & rmask(FP)) == 0);

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
    _nSlot = 0;
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

// Emit the code required to load a memory address into a register as follows:
// d = *(b+off)
// underrunProtect calls from this function can be disabled by setting chk to
// false. However, this function can use more than LD32_size bytes of space if
// the offset is out of the range of a LDR instruction; the maximum space this
// function requires for underrunProtect is 4+LD32_size.
void
Assembler::asm_ldr_chk(Register d, Register b, int32_t off, bool chk)
{
#ifdef NJ_ARM_VFP
    if (IsFpReg(d)) {
        FLDD_chk(d,b,off,chk);
        return;
    }
#endif

    NanoAssert(IsGpReg(d));
    NanoAssert(IsGpReg(b));

    // We can't use underrunProtect if the base register is the PC because
    // underrunProtect might move the PC if there isn't enough space on the
    // current page.
    NanoAssert((b != PC) || (!chk));

    if (isU12(off)) {
        // LDR d, b, #+off
        if (chk) underrunProtect(4);
        *(--_nIns) = (NIns)( COND_AL | (0x59<<20) | (b<<16) | (d<<12) | off );
    } else if (isU12(-off)) {
        // LDR d, b, #-off
        if (chk) underrunProtect(4);
        *(--_nIns) = (NIns)( COND_AL | (0x51<<20) | (b<<16) | (d<<12) | -off );
    } else {
        // The offset is over 4096 (and outside the range of LDR), so we need
        // to add a level of indirection to get the address into IP.

        // Because of that, we can't do a PC-relative load unless it fits within
        // the single-instruction forms above.

        NanoAssert(b != PC);
        NanoAssert(b != IP);

        if (chk) underrunProtect(4+LD32_size);

        *(--_nIns) = (NIns)( COND_AL | (0x79<<20) | (b<<16) | (d<<12) | IP );
        asm_ld_imm(IP, off, false);
    }

    asm_output("ldr %s, [%s, #%d]",gpn(d),gpn(b),(off));
}

// Emit the code required to load an immediate value (imm) into general-purpose
// register d. Optimal (MOV-based) mechanisms are used if the immediate can be
// encoded using ARM's operand 2 encoding. Otherwise, a slot is used on the
// literal pool and LDR is used to load the value.
//
// chk can be explicitly set to false in order to disable underrunProtect calls
// from this function; this allows the caller to perform the check manually.
// This function guarantees not to use more than LD32_size bytes of space.
void
Assembler::asm_ld_imm(Register d, int32_t imm, bool chk /* = true */)
{
    uint32_t    op2imm;

    NanoAssert(IsGpReg(d));

    // Attempt to encode the immediate using the second operand of MOV or MVN.
    // This is the simplest solution and generates the shortest and fastest
    // code, but can only encode a limited set of values.

    if (encOp2Imm(imm, &op2imm)) {
        // Use MOV to encode the literal.
        MOVis(d, op2imm, 0);
        return;
    }

    if (encOp2Imm(~imm, &op2imm)) {
        // Use MVN to encode the inverted literal.
        MVNis(d, op2imm, 0);
        return;
    }

    // Try to use simple MOV, MVN or MOV(W|T) instructions to load the
    // immediate. If this isn't possible, load it from memory.
    //  - We cannot use MOV(W|T) on cores older than the introduction of
    //    Thumb-2 or if the target register is the PC.
    if (IS_ARM_ARCH_THUMB2() && (d != PC)) {
        // ARMv6T2 and above have MOVW and MOVT.
        uint32_t    high_h = (uint32_t)imm >> 16;
        uint32_t    low_h = imm & 0xffff;

        if (high_h != 0) {
            // Load the high half-word (if necessary).
            MOVTi_chk(d, high_h, chk);
        }
        // Load the low half-word. This also zeroes the high half-word, and
        // thus must execute _before_ MOVT, and is necessary even if low_h is 0
        // because MOVT will not change the existing low half-word.
        MOVWi_chk(d, low_h, chk);

        return;
    }

    // We couldn't encode the literal in the instruction stream, so load it
    // from memory.

    // Because the literal pool is on the same page as the generated code, it
    // will almost always be within the ±4096 range of a LDR. However, this may
    // not be the case if _nSlot is at the start of the page and _nIns is at
    // the end because the PC is 8 bytes ahead of _nIns. This is unlikely to
    // happen, but if it does occur we can simply waste a word or two of
    // literal space.

    // We must do the underrunProtect before PC_OFFSET_FROM as underrunProtect
    // can move the PC if there isn't enough space on the current page!
    if (chk) {
        underrunProtect(LD32_size);
    }

    int offset = PC_OFFSET_FROM(_nSlot, _nIns-1);
    // If the offset is out of range, waste literal space until it is in range.
    while (offset <= -4096) {
        ++_nSlot;
        offset += sizeof(_nSlot);
    }
    NanoAssert(isS12(offset) && (offset < -8));

    // Write the literal.
    *(_nSlot++) = imm;

    // Load the literal.
    LDR_nochk(d,PC,offset);
    NanoAssert(uintptr_t(_nIns) + 8 + offset == uintptr_t(_nSlot-1));
    NanoAssert(*((int32_t*)_nSlot-1) == imm);
}

// Branch to target address _t with condition _c, doing underrun
// checks (_chk == 1) or skipping them (_chk == 0).
//
// Set the target address (_t) to 0 if the target is not yet known and the
// branch will be patched up later.
//
// If the jump is to a known address (with _t != 0) and it fits in a relative
// jump (±32MB), emit that.
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
    //nj_dprintf("B_cond_chk target: 0x%08x offset: %d @0x%08x\n", _t, offs, _nIns-1);

    #ifdef TM_MERGE
    // We don't patch conditional branches, and nPatchBranch can't cope with
    // them. We should therefore check that they are not generated at this
    // stage.
    NanoAssert((_t != 0) || (_c == AL));
    #endif

    // optimistically check if this will fit in 24 bits
    if (_chk && isS24(offs>>2) && (_t != 0)) {
            underrunProtect(4);
        // recalculate the offset, because underrunProtect may have
        // moved _nIns to a new page
            offs = PC_OFFSET_FROM(_t,_nIns-1);
    }

    // Emit one of the following patterns:
    //
    //  --- Short branch. This can never be emitted if the branch target is not
    //      known.
    //          B(cc)   ±32MB
    //
    //  --- Long unconditional branch.
    //          LDR     PC, #lit
    //  lit:    #target
    //
    //  --- Long conditional branch. Note that conditional branches will never
    //      be patched, so the nPatchBranch function doesn't need to know where
    //      the literal pool is located.
    //          LDRcc   PC, #lit
    //          ; #lit is in the literal pool at ++_nSlot
    //
    //  --- Long conditional branch (if !samepage(_nIns-1, _nSlot)).
    //          LDRcc   PC, #lit
    //          B       skip        ; Jump over the literal data.
    //  lit:    #target
    //  skip:   [...]

    if (isS24(offs>>2) && (_t != 0)) {
        // The underrunProtect for this was done above (if required by _chk).
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
        // Emit a pointer to the target as a literal in the instruction stream.
        *(--_nIns) = (NIns)(_t);
        // Emit a branch to skip over the literal. The PC value is 8 bytes
        // ahead of the executing instruction, so to branch two instructions
        // forward this must branch 8-8=0 bytes.
        *(--_nIns) = (NIns)( COND_AL | (0xA<<24) | 0x0 );
        // Emit the conditional branch.
        *(--_nIns) = (NIns)( ((_c)<<28) | (0x51<<20) | (PC<<16) | (PC<<12) | 0x0 );
        asm_output("b%s %p", _c == AL ? "" : condNames[_c], (void*)(_t));
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
#endif // NJ_ARM_VFP

/* Call this with targ set to 0 if the target is not yet known and the branch
 * will be patched up later.
 */
NIns*
Assembler::asm_branch(bool branchOnFalse, LInsp cond, NIns* targ)
{
    LOpcode condop = cond->opcode();
    NanoAssert(cond->isCond());
#ifdef NJ_SOFTFLOAT
    NanoAssert((condop < LIR_feq) || (condop > LIR_fge));
#endif

    // The old "never" condition code has special meaning on newer ARM cores,
    // so use "always" as a sensible default code.
    ConditionCode cc = AL;

    // Detect whether or not this is a floating-point comparison.
    bool    fp_cond;

    // Select the appropriate ARM condition code to match the LIR instruction.
    switch (condop)
    {
#ifdef NJ_ARM_VFP
        // Floating-point conditions. Note that the VFP LT/LE conditions
        // require use of the unsigned condition codes, even though
        // float-point comparisons are always signed.
        case LIR_feq:   cc = EQ;    fp_cond = true;     break;
        case LIR_flt:   cc = LO;    fp_cond = true;     break;
        case LIR_fle:   cc = LS;    fp_cond = true;     break;
        case LIR_fge:   cc = GE;    fp_cond = true;     break;
        case LIR_fgt:   cc = GT;    fp_cond = true;     break;
#endif
        // Standard signed and unsigned integer comparisons.
        case LIR_eq:    cc = EQ;    fp_cond = false;    break;
        case LIR_ov:    cc = VS;    fp_cond = false;    break;
        case LIR_lt:    cc = LT;    fp_cond = false;    break;
        case LIR_le:    cc = LE;    fp_cond = false;    break;
        case LIR_gt:    cc = GT;    fp_cond = false;    break;
        case LIR_ge:    cc = GE;    fp_cond = false;    break;
        case LIR_ult:   cc = LO;    fp_cond = false;    break;
        case LIR_ule:   cc = LS;    fp_cond = false;    break;
        case LIR_ugt:   cc = HI;    fp_cond = false;    break;
        case LIR_uge:   cc = HS;    fp_cond = false;    break;

        // Default case for invalid or unexpected LIR instructions.
        default:        cc = AL;    fp_cond = false;    break;
    }

    // Invert the condition if required.
    if (branchOnFalse)
        cc = OppositeCond(cc);

    // Ensure that we got a sensible condition code.
    NanoAssert((cc != AL) && (cc != NV));

    // Ensure that we don't hit floating-point LIR codes if VFP is disabled.
    NanoAssert(IS_ARM_ARCH_VFP() || !fp_cond);

    // Emit a suitable branch instruction.
    B_cond(cc, targ);

    // Store the address of the branch instruction so that we can return it.
    // asm_[f]cmp will move _nIns so we must do this now.
    NIns *at = _nIns;

#ifdef NJ_ARM_VFP
    if (fp_cond)
        asm_fcmp(cond);
    else
#endif
        asm_cmp(cond);

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
    LInsp   lhs = ins->oprnd1();
    LInsp   rhs = ins->oprnd2();

    RegisterMask    allow = GpRegs;

    // We always need the result register and the first operand register.
    Register        rr = prepResultReg(ins, allow);
    Reservation *   rA = getresv(lhs);
    Register        ra = UnknownReg;
    Register        rb = UnknownReg;

    // If this is the last use of lhs in reg, we can re-use the result reg.
    if (!rA || (ra = rA->reg) == UnknownReg)
        ra = findSpecificRegFor(lhs, rr);

    // Don't re-use the registers we've already allocated.
    NanoAssert(rr != UnknownReg);
    NanoAssert(ra != UnknownReg);
    allow &= ~rmask(rr);
    allow &= ~rmask(ra);

    // If the rhs is constant, we can use the instruction-specific code to
    // determine if the value can be encoded in an ARM instruction. If the
    // value cannot be encoded, it will be loaded into a register.
    //
    // Note that the MUL instruction can never take an immediate argument so
    // even if the argument is constant, we must allocate a register for it.
    //
    // Note: It is possible to use a combination of the barrel shifter and the
    // basic arithmetic instructions to generate constant multiplications.
    // However, LIR_mul is never invoked with a constant during
    // trace-tests.js so it is very unlikely to be worthwhile implementing it.
    if (rhs->isconst() && op != LIR_mul)
    {
        if ((op == LIR_add || op == LIR_iaddp) && lhs->isop(LIR_ialloc)) {
            // Add alloc+const. The result should be the address of the
            // allocated space plus a constant.
            Register    rs = prepResultReg(ins, allow);
            int         d = findMemFor(lhs) + rhs->imm32();

            NanoAssert(rs != UnknownReg);
            asm_add_imm(rs, FP, d);
        }

        int32_t imm32 = rhs->imm32();

        switch (op)
        {
            case LIR_iaddp: asm_add_imm(rr, ra, imm32);     break;
            case LIR_add:   asm_add_imm(rr, ra, imm32, 1);  break;
            case LIR_sub:   asm_sub_imm(rr, ra, imm32, 1);  break;
            case LIR_and:   asm_and_imm(rr, ra, imm32);     break;
            case LIR_or:    asm_orr_imm(rr, ra, imm32);     break;
            case LIR_xor:   asm_eor_imm(rr, ra, imm32);     break;
            case LIR_lsh:   LSLi(rr, ra, imm32);            break;
            case LIR_rsh:   ASRi(rr, ra, imm32);            break;
            case LIR_ush:   LSRi(rr, ra, imm32);            break;

            default:
                NanoAssertMsg(0, "Unsupported");
                break;
        }

        // We've already emitted an instruction, so return now.
        return;
    }

    // The rhs is either a register or cannot be encoded as a constant.

    if (lhs == rhs) {
        rb = ra;
    } else {
        rb = asm_binop_rhs_reg(ins);
        if (rb == UnknownReg)
            rb = findRegFor(rhs, allow);
        allow &= ~rmask(rb);
    }
    NanoAssert(rb != UnknownReg);

    switch (op)
    {
        case LIR_iaddp: ADDs(rr, ra, rb, 0);    break;
        case LIR_add:   ADDs(rr, ra, rb, 1);    break;
        case LIR_sub:   SUBs(rr, ra, rb, 1);    break;
        case LIR_and:   ANDs(rr, ra, rb, 0);    break;
        case LIR_or:    ORRs(rr, ra, rb, 0);    break;
        case LIR_xor:   EORs(rr, ra, rb, 0);    break;

        case LIR_mul:
            // ARMv5 and earlier cores cannot do a MUL where the first operand
            // is also the result, so we need a special case to handle that.
            //
            // We try to use rb as the first operand by default because it is
            // common for (rr == ra) and is thus likely to be the most
            // efficient case; if ra is no longer used after this LIR
            // instruction, it is re-used for the result register (rr).
            if (IS_ARM_ARCH_GT_V5() || (rr != rb)) {
                // Newer cores place no restrictions on the registers used in a
                // MUL instruction (compared to other arithmetic instructions).
                MUL(rr, rb, ra);
            } else {
                // config.arch is ARMv5 (or below) and rr == rb, so we must
                // find a different way to encode the instruction.

                // If possible, swap the arguments to avoid the restriction.
                if (rr != ra) {
                    // We know that rr == rb, so this will be something like
                    // rX = rY * rX.
                    MUL(rr, ra, rb);
                } else {
                    // We're trying to do rX = rX * rX, so we must use a
                    // temporary register to achieve this correctly on ARMv5.

                    // The register allocator will never allocate IP so it will
                    // be safe to use here.
                    NanoAssert(ra != IP);
                    NanoAssert(rr != IP);

                    // In this case, rr == ra == rb.
                    MUL(rr, IP, rb);
                    MOV(IP, ra);
                }
            }
            break;
        
        // The shift operations need a mask to match the JavaScript
        // specification because the ARM architecture allows a greater shift
        // range than JavaScript.
        case LIR_lsh:
            LSL(rr, ra, IP);
            ANDi(IP, rb, 0x1f);
            break;
        case LIR_rsh:
            ASR(rr, ra, IP);
            ANDi(IP, rb, 0x1f);
            break;
        case LIR_ush:
            LSR(rr, ra, IP);
            ANDi(IP, rb, 0x1f);
            break;
        default:
            NanoAssertMsg(0, "Unsupported");
            break;
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
                LDR(r, FP, d);
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
    asm_ld_imm(rr, ins->imm32());
}

void
Assembler::asm_ret(LIns *ins)
{
    genEpilogue();

    // Pop the stack frame.
    MOV(SP,FP);

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
