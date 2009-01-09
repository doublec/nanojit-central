/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*- */
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

#if defined FEATURE_NANOJIT && defined NANOJIT_PPC

namespace nanojit
{
	const Register Assembler::retRegs[] = { R3, R4 }; // high=R3, low=R4 
	const Register Assembler::argRegs[] = { R3, R4, R5, R6, R7, R8, R9, R10 };
	const Register Assembler::savedRegs[] = { R14, R15, R16, R17, R18, R19,
		R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31 };
	const char *regNames[] = {
		"r0",  "sp",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
		"r8",  "r9",  "r10", "r11", "r12", "fp",  "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
		"f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
		"f8",  "f9",  "f10", "f11", "f12", "f13", "f14", "f15",
		"f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
		"f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31"
	};
	const char *bitNames[] = { "lt", "gt", "eq", "so" };

	#define TODO(x) do{ printf(#x); NanoAssertMsgf(false, "%s", #x); } while(0)

	/* 
	 * see http://developer.apple.com/documentation/developertools/Conceptual/LowLevelABI/Articles/32bitPowerPC.html
	 * stack layout (higher address going down)
	 * sp ->	out linkage area
	 * 			out parameter area
	 *			local variables
	 *			saved registers
	 * sp' ->	in linkage area
	 *			in parameter area
	 *
	 * linkage area
	 * sp+0		saved sp
	 * sp+4    	saved cr
	 * sp+8    	saved lr
	 * sp+12   	reserved
	 */

	const int linkage_size = 24;
	const int lr_offset = 8; // linkage.lr
	const int cr_offset = 4; // linkage.cr

	NIns* Assembler::genPrologue() {
		// mflr r0
		// stw r0, 8(sp)
		// stwu sp, -framesize(sp)

		uint32_t stackNeeded = max_param_size + linkage_size +
			STACK_GRANULARITY * _activation.highwatermark;
		uint32_t aligned = alignUp(stackNeeded, NJ_ALIGN_STACK);

		UNLESS_PEDANTIC( if (isS16(aligned)) {
			STWU(SP, -aligned, SP); // *(sp-aligned) = sp; sp -= aligned
		} else ) {
			STWUX(SP, SP, R0);
			asm_li(R0, -aligned);
		}

		NIns *patchEntry = _nIns;
		MR(FP,SP);				// save SP to use as a FP
		STW(FP, cr_offset, SP); // cheat and save our FP in linkage.cr
		STW(R0, lr_offset, SP); // save LR in linkage.lr
		MFLR(R0);

		// pad start addr to 8byte
		if (intptr_t(_nIns) & 7)
			NOP();

		return patchEntry;
	}

	NIns* Assembler::genEpilogue() {
		max_param_size = 0;
		BLR();
		MTLR(R0);
		LWZ(R0, lr_offset, SP);
		LWZ(FP, cr_offset, SP); // restore FP from linkage.cr
		MR(SP,FP);
		return _nIns;
	}

	void Assembler::asm_qjoin(LIns *ins) {
		int d = findMemFor(ins);
		NanoAssert(d && isS16(d));
		LIns* lo = ins->oprnd1();
		LIns* hi = ins->oprnd2();
                            
		Register r = findRegFor(hi, GpRegs);
		STW(r, d+4, FP);

		// okay if r gets recycled.
		r = findRegFor(lo, GpRegs);
		STW(r, d, FP);
		freeRsrcOf(ins, false); // if we had a reg in use, emit a ST to flush it to mem
	}

	void Assembler::asm_ld(LIns *ins) {
        LIns* base = ins->oprnd1();
        LIns* disp = ins->oprnd2();
        Register rr = prepResultReg(ins, GpRegs);
        int d = disp->constval();
		Register ra = getBaseReg(base, d, GpRegs);
		
		#if !PEDANTIC
		if (isS16(d)) {
			if (ins->isop(LIR_ldcb)) {
				LBZ(rr, d, ra);
			} else {
				LWZ(rr, d, ra);
			}
			return;
		}
		#endif

		// general case
		underrunProtect(12);
		LWZX(rr, ra, R0); // rr = [ra+R0]
		asm_li(R0,d);
	}

	void Assembler::asm_store32(LIns *value, int32_t dr, LIns *base) {
		Register rs = findRegFor(value, GpRegs);
		Register ra = value == base ? rs : getBaseReg(base, dr, GpRegs & ~rmask(rs));

	#if !PEDANTIC
		if (isS16(dr)) {
			STW(rs, dr, ra);
			return;
		}
	#endif

		// general case store, any offset size
		STWX(rs, ra, R0);
		asm_li(R0, dr);
	}

	void Assembler::asm_load64(LIns *ins) {
		LIns* base = ins->oprnd1();
		Register rr = prepResultReg(ins, FpRegs);
		int dr = ins->oprnd2()->constval();
		Register ra = getBaseReg(base, dr, GpRegs);

	#if !PEDANTIC
		if (isS16(dr)) {
			LFD(rr, dr, ra);
			return;
		}
	#endif
		// general case load64
		LFDX(rr, ra, R0);
		asm_li(R0, dr);
	}

	void Assembler::asm_li(Register r, int32_t imm) {
	#if !PEDANTIC
		if (isS16(imm)) {
			LI(r, imm);
			return;
		}
		if ((imm & 0xffff) == 0) {
			imm = uint32_t(imm) >> 16;
			LIS(r, imm);
			return;
		}
	#endif
		asm_li32(r, imm);
	}

	void Assembler::asm_li32(Register r, int32_t imm) {
		// general case
		// TODO use ADDI instead of ORI if r != r0, impl might have 3way adder
		ORI(r, r, imm);
		LIS(r, imm>>16);
	}

	void Assembler::asm_store64(LIns *value, int32_t dr, LIns *base) {
		NanoAssert(value->isQuad());
		Register ra = getBaseReg(base, dr, GpRegs);

	#if !PEDANTIC
		if (value->isop(LIR_quad) && isS16(dr) && isS16(dr+4)) {
			// quad constant and short offset
			uint64_t q = value->constvalq();
			STW(R0, dr, ra);   // hi
			asm_li(R0, int32_t(q>>32)); // hi
			STW(R0, dr+4, ra); // lo
			asm_li(R0, int32_t(q));     // lo
			return;
		}
		if (value->isop(LIR_qjoin) && isS16(dr) && isS16(dr+4)) {
			// short offset and qjoin(lo,hi) - store lo & hi separately
			RegisterMask allow = GpRegs & ~rmask(ra);
			LIns *lo = value->oprnd1();
			Register rlo = findRegFor(lo, allow);
			LIns *hi = value->oprnd2();
			Register rhi = hi == lo ? rlo : findRegFor(hi, allow & ~rmask(rlo));
			STW(rhi, dr, ra); // hi
			STW(rlo, dr+4, ra); // lo
			return;
		}
	#endif // !PEDANTIC

		// general case for any value
		Register rs = findRegFor(value, FpRegs);

	#if !PEDANTIC
		if (isS16(dr)) {
			// short offset
			STFD(rs, dr, ra);
			return;
		}
	#endif

		// general case for any offset
		STFDX(rs, ra, R0);
		asm_li(R0, dr);
	}

	void Assembler::asm_cond(LIns *ins) {
		LOpcode op = ins->opcode();
		LIns *a = ins->oprnd1();
		LIns *b = ins->oprnd2();
		ConditionRegister cr = CR7;
		Register r = prepResultReg(ins, GpRegs);
		switch (op) {
		case LIR_eq: case LIR_feq:
			EXTRWI(r, r, 1, 4*cr+COND_eq); // extract CR7.eq
			MFCR(r);
			break;
		case LIR_lt: case LIR_ult: case LIR_flt: case LIR_fle:
			EXTRWI(r, r, 1, 4*cr+COND_lt); // extract CR7.lt
			MFCR(r);
			break;
		case LIR_gt: case LIR_ugt: case LIR_fgt: case LIR_fge:
			EXTRWI(r, r, 1, 4*cr+COND_gt); // extract CR7.gt
			MFCR(r);
			break;
		case LIR_le: case LIR_ule:
			EXTRWI(r, r, 1, 4*cr+COND_eq); // extract CR7.eq
			MFCR(r);
			CROR(CR7, eq, lt, eq);
			break;
		case LIR_ge: case LIR_uge:
			EXTRWI(r, r, 1, 4*cr+COND_eq); // select CR7.eq
			MFCR(r);
			CROR(CR7, eq, gt, eq);
			break;
		default:
			debug_only(outputf("%s",lirNames[ins->opcode()]);)
			TODO(asm_cond);
			break;
		}
		asm_cmp(op, a, b, cr);
	}

	void Assembler::asm_fcond(LIns *ins) {
		asm_cond(ins);
	}

	#define isS14(i) ((((i)<<18)>>18) == (i))

	NIns* Assembler::asm_branch(bool onfalse, LIns *cond, NIns * const targ) {
        LOpcode condop = cond->opcode();
        NanoAssert(cond->isCond());

		// powerpc offsets are based on the address of the branch instruction
		NIns *patch;
	#if !PEDANTIC
		ptrdiff_t bd = targ - (_nIns-1);
		if (targ && isS24(bd))
			patch = asm_branch_near(onfalse, cond, targ);
		else
	#endif
			patch = asm_branch_far(onfalse, cond, targ);
		asm_cmp(condop, cond->oprnd1(), cond->oprnd2(), CR7);
		return patch;
	}

	NIns* Assembler::asm_branch_near(bool onfalse, LIns *cond, NIns * const targ) {
		NanoAssert(targ != 0);
		underrunProtect(4);
		ptrdiff_t bd = targ - (_nIns-1);
		NIns *patch = 0;
		if (!isS14(bd)) {
			underrunProtect(8);
			bd = targ - (_nIns-1);
			if (isS24(bd)) {
				// can't fit conditional branch offset into 14 bits, but
				// we can fit in 24, so invert the condition and branch
				// around an unconditional jump
				verbose_only(verbose_outputf("%p:", _nIns);)
				NIns *skip = _nIns;
				B(bd);
				patch = _nIns; // this is the patchable branch to the given target
				onfalse = !onfalse;
				bd = skip - (_nIns-1);
				NanoAssert(isS14(bd));
				verbose_only(verbose_outputf("branch24");)
			}
			else {
				// known far target
				return asm_branch_far(onfalse, cond, targ);
			}
		}
		ConditionRegister cr = CR7;
		switch (cond->opcode()) {
		case LIR_eq: case LIR_feq:
			if (onfalse) BNE(cr,bd); else BEQ(cr,bd);
			break;
		case LIR_lt: case LIR_ult:
		case LIR_flt: case LIR_fle:
			if (onfalse) BNL(cr,bd); else BLT(cr,bd);
			break;
		case LIR_le: case LIR_ule:
			if (onfalse) BGT(cr,bd); else BLE(cr,bd);
			break;
		case LIR_gt: case LIR_ugt:
		case LIR_fgt: case LIR_fge:
			if (onfalse) BNG(cr,bd); else BGT(cr,bd);
			break;
		case LIR_ge: case LIR_uge:
			if (onfalse) BLT(cr,bd); else BGE(cr,bd);
			break;
		default:
			debug_only(outputf("%s",lirNames[cond->opcode()]);)
			TODO(unknown_cond);
		}
		if (!patch)
			patch = _nIns;
        return patch;
	}

	// general case branch to any address (using CTR)
	NIns *Assembler::asm_branch_far(bool onfalse, LIns *cond, NIns * const targ) {
		LOpcode condop = cond->opcode();
		ConditionRegister cr = CR7;
		underrunProtect(16);
		switch (condop) {
		case LIR_eq: case LIR_feq:
			if (onfalse) BNECTR(cr); else BEQCTR(cr);
			break;
		case LIR_lt: case LIR_ult:
		case LIR_flt: case LIR_fle:
			if (onfalse) BNLCTR(cr); else BLTCTR(cr);
			break;
		case LIR_le: case LIR_ule:
			if (onfalse) BGTCTR(cr); else BLECTR(cr);
			break;
		case LIR_gt: case LIR_ugt:
		case LIR_fgt: case LIR_fge:
			if (onfalse) BNGCTR(cr); else BGTCTR(cr);
			break;
		case LIR_ge: case LIR_uge:
			if (onfalse) BLTCTR(cr); else BGECTR(cr);
			break;
		default:
			debug_only(outputf("%s",lirNames[condop]);)
			TODO(unknown_cond);
		}
		MTCTR(R0);
		asm_li32(R0, (int)targ);
		return _nIns;
	}

	void Assembler::asm_cmp(LOpcode condop, LIns *a, LIns *b, ConditionRegister cr) {
		RegisterMask allow = condop >= LIR_feq && condop <= LIR_fge ? FpRegs : GpRegs;
		Register ra = findRegFor(a, allow);

	#if !PEDANTIC
		if (b->isconst()) {
			int32_t d = b->constval();
			if (isS16(d) && condop >= LIR_eq && condop <= LIR_ge) {
				CMPWI(cr, ra, d);
				return;
			}
			if (isU16(d) && (condop == LIR_eq || condop >= LIR_ult && condop <= LIR_uge)) {
				CMPLWI(cr, ra, d);
				return;
			}
		}
	#endif

		// general case
		Register rb = b==a ? ra : findRegFor(b, allow & ~rmask(ra));
		if (condop >= LIR_eq && condop <= LIR_ge)
			CMPW(cr, ra, rb);
		else if (condop >= LIR_ult && condop <= LIR_uge)
			CMPLW(cr, ra, rb);
		else if (condop >= LIR_feq && condop <= LIR_fge) {
			// set the lt/gt bit for fle/fge.  We don't do this for
			// int/uint because in those cases we can invert the branch condition.
			// for float, we can't because of unordered comparisons
			if (condop == LIR_fle)
				CROR(cr, lt, lt, eq); // lt = lt|eq
			else if (condop == LIR_fge)
				CROR(cr, gt, gt, eq); // gt = gt|eq
			FCMPU(cr, ra, rb);
		}
		else
			TODO(asm_cmp);
	}

	void Assembler::asm_ret(LIns *ins) {
		UNLESS_PEDANTIC( if (_nIns != _epilogue) ) {
			br(_epilogue, 0);
		}
		assignSavedParams();
		LIns *value = ins->oprnd1();
		Register r = ins->isop(LIR_ret) ? R3 : F1;
		findSpecificRegFor(value, r);
	}

	void Assembler::asm_nongp_copy(Register r, Register s) {
		// PPC doesn't support any GPR<->FPR moves
		NanoAssert((rmask(r) & FpRegs) && (rmask(s) & FpRegs));
		FMR(r, s);
	}

	void Assembler::asm_restore(LIns *i, Reservation *resv, Register r) {
		int d;
		if (i->isop(LIR_alloc)) {
			d = disp(resv);
			ADDI(r, FP, d);
		}
		else if (i->isconst()) {
			if (!resv->arIndex) {
				reserveFree(i);
			}
			asm_li(r, i->constval());
		}
		else {
			d = findMemFor(i);
			if (IsFpReg(r)) {
				LFD(r, d, FP);
			} else {
				LWZ(r, d, FP);
			}
			verbose_only(
				if (_verbose)
					outputf("        restore %s",_thisfrag->lirbuf->names->formatRef(i));
			)
		}
	}

	Register Assembler::asm_prep_fcall(Reservation*, LIns *ins) {
		return prepResultReg(ins, rmask(F1));
	}

	void Assembler::asm_int(LIns *ins) {
        Register rr = prepResultReg(ins, GpRegs);
		asm_li(rr, ins->constval());
	}

	void Assembler::asm_short(LIns *ins) {
		int32_t val = ins->imm16();
        Register rr = prepResultReg(ins, GpRegs);
		LI(rr, val);
	}

	void Assembler::asm_fneg(LIns *ins) {
        Register rr = prepResultReg(ins, FpRegs);
		Register ra = findRegFor(ins->oprnd1(), FpRegs);
		FNEG(rr,ra);
	}

	void Assembler::asm_param(LIns *ins) {
        uint32_t a = ins->imm8();
        uint32_t kind = ins->imm8b();
        if (kind == 0) {
            // ordinary param
            // first eight args always in R3..R10 for PPC
            if (a < 8) {
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

	void Assembler::asm_call(LIns *ins) {
		const CallInfo* call = ins->callInfo();
		ArgSize sizes[MAXARGS];
		uint32_t argc = call->get_sizes(sizes);

		bool indirect;
		if (!(indirect = call->isIndirect())) {
			verbose_only(if (_verbose)
				outputf("        %p:", _nIns);
			)
			br((NIns*)call->_address, 1);
		} else {
			// Indirect call: we assign the address arg to R11 since it's not
			// used for regular arguments, and is otherwise scratch since it's
			// clobberred by the call.
			underrunProtect(8); // underrunProtect might clobber CTR
			BCTRL();
			MTCTR(R11);
			asm_regarg(ARGSIZE_LO, ins->arg(--argc), R11);
		}

		int param_size = 0;
		if (call->isInterface()) {
			// interface thunk calling convention: put iid in R6 (4th param)
			argc--;
			asm_regarg(ARGSIZE_LO, ins->arg(argc), R6);
			param_size += 4;
		}

		Register r = R3;
		Register fr = F1;
		for(uint32_t i = 0; i < argc; i++) {
			uint32_t j = argc - i - 1;
			ArgSize sz = sizes[j];
			LInsp arg = ins->arg(j);
			if (sz == ARGSIZE_LO) {
				// int32 arg
				if (r <= R10) {
					asm_regarg(sz, arg, r);
					r = nextreg(r);
					param_size += 4;
				} else {
					// put arg on stack
					TODO(stack_int32);
				}
			} else if (sz == ARGSIZE_F) {
				// double
				if (fr <= F13) {
					asm_regarg(sz, arg, fr);
					fr = nextreg(fr);
					r = nextreg(nextreg(r)); // skip 2 gpr's
					param_size += 8;
				} else {
					// put arg on stack
					TODO(stack_double);
				}
			} else {
				TODO(ARGSIZE_Q);
			}
		}
		if (param_size > max_param_size)
			max_param_size = param_size;
	}

    void Assembler::asm_regarg(ArgSize sz, LInsp p, Register r)
    {
        NanoAssert(r != UnknownReg);
        if (sz == ARGSIZE_Q) {
			// ref arg - need to send addr of quad
			TODO(ARGSIZE_Q);
		}
        else if (sz == ARGSIZE_LO)
        {
            // arg goes in specific register
            if (p->isconst()) {
				asm_li(r, p->constval());
            } else {
                Reservation* rA = getresv(p);
                if (rA) {
                    if (rA->reg == UnknownReg) {
                        // load it into the arg reg
                        int d = findMemFor(p);
                        if (p->isop(LIR_alloc)) {
							NanoAssert(isS16(d));
							ADDI(r, FP, d);
                        } else {
							LWZ(r, d, FP);
                        }
                    } else {
                        // it must be in a saved reg
                        MR(r, rA->reg);
                    }
                } 
                else {
                    // this is the last use, so fine to assign it
                    // to the scratch reg, it's dead after this point.
                    findSpecificRegFor(p, r);
                }
            }
        }
        else {
			NanoAssert(sz == ARGSIZE_F);
			Reservation* rA = getresv(p);
			if (rA) {
				if (rA->reg == UnknownReg) {
					// load it into the arg reg
					int d = findMemFor(p);
					LFD(r, d, FP);
				} else {
					// it must be in a saved reg
					FMR(r, rA->reg);
				}
			} 
			else {
				// this is the last use, so fine to assign it
				// to the scratch reg, it's dead after this point.
				findSpecificRegFor(p, r);
			}
        }
    }

	void Assembler::asm_spill(Register rr, int d, bool /* pop */, bool /* quad */) {
		if (d) {
			if (IsFpReg(rr)) {
				STFD(rr, d, FP);
			} else {
				STW(rr, d, FP);
			}
		}
	}

	void Assembler::asm_arith(LIns *ins) {
        LOpcode op = ins->opcode();         
        LInsp lhs = ins->oprnd1();
        LInsp rhs = ins->oprnd2();
		RegisterMask allow = GpRegs;
        Register rr = prepResultReg(ins, allow);
		Register ra = findRegFor(lhs, GpRegs);

		if (rhs->isconst()) {
			int32_t rhsc = rhs->constval();
			if (isS16(rhsc)) {
				// ppc arith immediate ops sign-exted the imm16 value
				switch (op) {
				case LIR_add: case LIR_addp:
					ADDI(rr, ra, rhsc);
					return;
				case LIR_sub:
					SUBI(rr, ra, rhsc);
					return;
				case LIR_mul:
					MULLI(rr, ra, rhsc);
					return;
				}
			}
			if (isU16(rhsc)) {
				// ppc logical immediate zero-extend the imm16 value
				switch (op) {	
				case LIR_or:
					ORI(rr, ra, rhsc);
					return;
				case LIR_and:
					ANDI(rr, ra, rhsc);
					return;
				case LIR_xor:
					XORI(rr, ra, rhsc);
					return;
				}
			}
			
			// LIR shift ops only use last 5bits of shift const
			switch (op) {
			case LIR_lsh:
				SLWI(rr, ra, rhsc&31);
				return;
			case LIR_ush:
				SRWI(rr, ra, rhsc&31);
				return;
			case LIR_rsh:
				SRAWI(rr, ra, rhsc&31);	
				return;
			}
		}
		
		// general case, put rhs in register
		Register rb = rhs==lhs ? ra : findRegFor(rhs, GpRegs&~rmask(ra));
		switch (op) {
			case LIR_add:
			case LIR_addp: ADD(rr, ra, rb);		break;
			case LIR_and:  AND(rr, ra, rb);		break;
			case LIR_or:   OR(rr, ra, rb);		break;
			case LIR_sub:  SUBF(rr, rb, ra);	break;
			case LIR_xor:  XOR(rr, ra, rb);		break;
			case LIR_lsh:  SLW(rr, ra, R0);		ANDI(R0, rb, 31);	break;
			case LIR_rsh:  SRAW(rr, ra, R0);	ANDI(R0, rb, 31);	break;
			case LIR_ush:  SRW(rr, ra, R0);		ANDI(R0, rb, 31);	break;
			case LIR_mul:  MULLW(rr, ra, rb);	break;
			default:
				debug_only(outputf("%s",lirNames[op]);)
				TODO(asm_arith);
		}
	}

	void Assembler::asm_fop(LIns *ins) {
        LOpcode op = ins->opcode();         
        LInsp lhs = ins->oprnd1();
        LInsp rhs = ins->oprnd2();
		RegisterMask allow = FpRegs;
        Register rr = prepResultReg(ins, allow);
		Reservation *rA, *rB;
		findRegFor2(allow, lhs, rA, rhs, rB);
		Register ra = rA->reg;
		Register rb = rB->reg;
		switch (op) {
			case LIR_fadd: FADD(rr, ra, rb); break;
			case LIR_fsub: FSUB(rr, ra, rb); break;
			case LIR_fmul: FMUL(rr, ra, rb); break;
			case LIR_fdiv: FDIV(rr, ra, rb); break;
			default:
				debug_only(outputf("%s",lirNames[op]);)
				TODO(asm_fop);
		}
	}

	void Assembler::asm_i2f(LIns *ins) {
		Register r = prepResultReg(ins, FpRegs);
		Register v = findRegFor(ins->oprnd1(), GpRegs);
		const int d = 16; // natural aligned

		FSUB(r, r, F0);
		LFD(r, d, SP); // scratch area in outgoing linkage area
		STW(R0, d+4, SP);
		XORIS(R0, v, 0x8000);
		LFD(F0, d, SP);
		STW(R0, d+4, SP);
		LIS(R0, 0x8000);
		STW(R0, d, SP);
		LIS(R0, 0x4330);
	}

	void Assembler::asm_u2f(LIns *ins) {
		Register r = prepResultReg(ins, FpRegs);
		Register v = findRegFor(ins->oprnd1(), GpRegs);
		const int d = 16;

		FSUB(r, r, F0);
		LFD(F0, d, SP);
		STW(R0, d+4, SP);
		LI(R0, 0);
		LFD(r, d, SP);
		STW(v, d+4, SP);
		STW(R0, d, SP);
		LIS(R0, 0x4330);
	}

	void Assembler::asm_quad(LIns *ins) {
		union {
			double d;
			struct {
				int32_t hi, lo;
			} w;
		};
		d = ins->constvalf();
		Register r = prepResultReg(ins, FpRegs);
		LFD(r, 12, SP);
		STW(R0, 12, SP);
		asm_li(R0, w.hi);
		STW(R0, 16, SP);
		asm_li(R0, w.lo);
	}

	void Assembler::br(NIns* addr, int link) {
		// powerpc offsets are based on the address of the branch instruction
		ptrdiff_t offset;
		if (!addr) {
			// will patch later
			offset = 0;
		} else {
			underrunProtect(4);       // ensure _nIns is addr of Bx
			offset = addr - (_nIns-1); // we want ptr diff's implicit >>2 here
		}

		#if !PEDANTIC
		if (isS24(offset)) {
			Bx(offset, 0, link); // b addr or bl addr
			return;
		}
		ptrdiff_t absaddr = addr - (NIns*)0; // ptr diff implies >>2
		if (isS24(absaddr)) {
			Bx(absaddr, 1, link); // ba addr or bla addr
			return;
		}
		#endif // !PEDANTIC

		// far jump.
		// can't have a page break in this sequence, because the break
		// would also clobber ctr and r2.  We use R2 here because it's not available
		// to the register allocator, and we use R0 everywhere else as scratch, so using
		// R2 here avoids clobbering anything else besides CTR.
		underrunProtect(16);
		BCTR(link);
		MTCTR(R2);
		asm_li32(R2, intptr_t(addr)); // 2 instructions
	}

	void Assembler::underrunProtect(int bytes) {
		NanoAssertMsg(bytes<=LARGEST_UNDERRUN_PROT, "constant LARGEST_UNDERRUN_PROT is too small"); 
		if (!_nSlot) {
			_nSlot = pageDataStart(_nIns);
		}
        int instr = (bytes + sizeof(NIns) - 1) / sizeof(NIns);
		NIns *top = (NIns*)(_nSlot + 1);
		NIns *pc = _nIns;

	#if PEDANTIC
		// pedanticTop is based on the last call to underrunProtect; any time we call
		// underrunProtect and would use more than what's already protected, then insert
		// a page break jump.  Sometimes, this will be to a new page, usually it's just
		// the next instruction and the only effect is to clobber R2 & CTR

		NanoAssert(pedanticTop >= top);
		if (pc - instr < pedanticTop) {
			// no page break required, but insert a far branch anyway just to be difficult
            const int br_size = 4;
			if (pc - instr - br_size < top) {
				// really do need a page break
				verbose_only(if (_verbose) outputf("newpage %p:", pc);)
				_nIns = pageAlloc(_inExit);
				_nSlot = pageDataStart(_nIns-1);
			}
			// now emit the jump, but make sure we won't need another page break. 
			// we're pedantic, but not *that* pedantic.
			pedanticTop = _nIns - br_size;
			br(pc, 0);
			pedanticTop = _nIns - instr;
		}
	#else
		if (pc - instr < top) {
			verbose_only(if (_verbose) outputf("newpage %p:", pc);)
			_nIns = pageAlloc(_inExit);
			_nSlot = pageDataStart(_nIns-1);
			// this jump will call underrunProtect again, but since we're on a new
			// page, nothing will happen.
			br(pc, 0);
		}
	#endif
	}

	void Assembler::asm_cmov(LIns *ins) {
        NanoAssert(ins->opcode() == LIR_cmov);
        LIns* cond = ins->oprnd1();
        NanoAssert(cond->isCmp());
        LIns* values = ins->oprnd2();
        NanoAssert(values->opcode() == LIR_2);
        LIns* iftrue = values->oprnd1();
        LIns* iffalse = values->oprnd2();
        NanoAssert(!iftrue->isQuad() && !iffalse->isQuad());
        
        Register rr = prepResultReg(ins, GpRegs);
		findSpecificRegFor(iftrue, rr);
		Register rf = findRegFor(iffalse, GpRegs & ~rmask(rr));
		NIns *after = _nIns;
		verbose_only(if (_verbose) outputf("%p:",after);)
		MR(rr, rf);
		asm_branch(false, cond, after);
	}

	RegisterMask Assembler::hint(LIns *i, RegisterMask allow) {
		LOpcode op = i->opcode();
		RegisterMask prefer = ~0LL;
		if (op == LIR_call)
			prefer = rmask(R3);
		else if (op == LIR_fcall)
			prefer = rmask(F1);
		else if (op == LIR_param) {
			if (i->imm8() < 8) {
				prefer = rmask(argRegs[i->imm8()]);
			}
		}
		// narrow the allow set to whatever is preferred and also free
		if (_allocator.free & allow & prefer)
			allow &= prefer;
		return allow;
	}

	void Assembler::asm_neg_not(LIns *ins) {
        Register rr = prepResultReg(ins, GpRegs);
		Register ra = findRegFor(ins->oprnd1(), GpRegs);
		if (ins->isop(LIR_neg)) {
			NEG(rr, ra);
		} else {
			NOT(rr, ra);
		}
	}

	void Assembler::nInit(AvmCore*) {
	}

	void Assembler::nativePageSetup() {
		_nSlot = 0;
		_nExitSlot = 0;
	}

	void Assembler::nativePageReset() {
		if (!_nIns) {
			_nIns     = pageAlloc();
			IF_PEDANTIC( pedanticTop = _nIns; )
		}
		if (!_nExitIns) {
			_nExitIns = pageAlloc(true);
		}
		
		if (!_nSlot)
		{
			// This needs to be done or the samepage macro gets confused; pageAlloc
			// gives us a pointer to just past the end of the page.
			_nIns--;
			_nExitIns--;

			// constpool starts at top of page and goes down,
			// code starts at bottom of page and moves up
			_nSlot = pageDataStart(_nIns);
		}
	}

	void Assembler::nPatchBranch(NIns *branch, NIns *target) {
		// ppc relative offsets are based on the addr of the branch instruction
		ptrdiff_t bd = target - branch;
		if (branch[0] == PPC_b) {
			// unconditional, 24bit offset.  Whoever generated the unpatched jump
			// must have known the final size would fit in 24bits!  otherwise the
			// jump would be (lis,ori,mtctr,bctr) and we'd be patching the lis,ori.
			NanoAssert(isS24(bd));
			branch[0] |= (bd & 0xffffff) << 2;
		}
		else if ((branch[0] & PPC_bc) == PPC_bc) {
			// conditional, 14bit offset. Whoever generated the unpatched jump
			// must have known the final size would fit in 14bits!  otherwise the
			// jump would be (lis,ori,mtctr,bcctr) and we'd be patching the lis,ori below.
			NanoAssert(isS14(bd));
			NanoAssert(((branch[0] & 0x3fff)<<2) == 0);
			branch[0] |= (bd & 0x3fff) << 2;
		}
		else if ((branch[0] & ~(31<<21)) == PPC_addis) {
			// general branch, using lis,ori to load the const addr.
			// patch a lis,ori sequence with a 32bit value
			Register rd = Register((branch[0] >> 21) & 31);
			NanoAssert(branch[1] == PPC_ori | GPR(rd)<<21 | GPR(rd)<<16);
			int32_t imm = (int32_t) target;
			branch[0] = PPC_addis | GPR(rd)<<21 | uint16_t(imm >> 16); // lis rd, imm >> 16
			branch[1] = PPC_ori | GPR(rd)<<21 | GPR(rd)<<16 | uint16_t(imm); // ori rd, rd, imm & 0xffff
		}
		else {
			TODO(unknown_patch);
		}
	}

	static int cntzlw(int set) {
		// On PowerPC, prefer higher registers, to minimize
		// size of nonvolatile area that must be saved.
		register Register i;
		#ifdef __GNUC__
		asm ("cntlzw %0,%1" : "=r" (i) : "r" (set));
		#else // __GNUC__
		# error("unsupported compiler")
		#endif // __GNUC__
		return 31-i;
	}

	Register Assembler::nRegisterAllocFromSet(RegisterMask set) {
		Register i;
		// note, deliberate truncation of 64->32 bits
		if (set & 0xffffffff) {
			i = Register(cntzlw(int(set))); // gp reg
		} else {
			i = Register(32+cntzlw(int(set>>32))); // fp reg
		}
		_allocator.free &= ~rmask(i);
		return i;
	}

	void Assembler::nRegisterResetAll(RegAlloc &regs) {
		regs.clear();
		regs.used = 0;
		regs.free = SavedRegs | 0x1ff8 /* R3-12 */ | 0x3ffe00000000LL /* F1-13 */;
		debug_only(regs.managed = regs.free);
	}

	void Assembler::nMarkExecute(Page* page, int flags) {
		static const int kProtFlags[4] = 
		{
			PROT_READ,						// 0
			PROT_READ|PROT_WRITE,			// PAGE_WRITE
			PROT_READ|PROT_EXEC,			// PAGE_EXEC
			PROT_READ|PROT_WRITE|PROT_EXEC	// PAGE_EXEC|PAGE_WRITE
		};
		int prot = kProtFlags[flags & (PAGE_WRITE|PAGE_EXEC)];
		intptr_t addr = (intptr_t)page;
		addr &= ~((uintptr_t)NJ_PAGE_SIZE - 1);
		NanoAssert(addr == (intptr_t)page);
		if (mprotect((void *)addr, NJ_PAGE_SIZE, prot) == -1) 
		{
			// todo: we can't abort or assert here, we have to fail gracefully.
			NanoAssertMsg(false, "FATAL ERROR: mprotect(PROT_EXEC) failed\n");
			abort();
		}
	}

	void Assembler::asm_loop(LIns*, NInsList&) {
		TODO(asm_loop);
	}

	void Assembler::asm_qlo(LIns*) {
		TODO(asm_qlo);
	}

	void Assembler::asm_qhi(LIns*) {
		TODO(asm_qhi);
	}

	void Assembler::nFragExit(LIns*) {
		TODO(nFragExit);
	}

	NIns* Assembler::asm_adjustBranch(NIns*, NIns*) {
		TODO(asm_adjustBranch);
		return 0;
	}

} // namespace nanojit

#endif // FEATURE_NANOJIT && AVMPLUS_PPC
