/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: t; tab-width: 4 -*- */
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
 *   Mozilla TraceMonkey Team
 *   Asko Tontti <atontti@cc.hut.fi>
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

#ifdef _MSC_VER
	// disable some specific warnings which are normally useful, but pervasive in the code-gen macros
	#pragma warning(disable:4310) // cast truncates constant value
#endif

namespace nanojit
{
	#if defined FEATURE_NANOJIT && defined NANOJIT_IA32

	#ifdef NJ_VERBOSE
		const char *regNames[] = {
			"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
			"xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
			"f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7"
		};
	#endif

	#define TODO(x) do{ verbose_only(outputf(#x);) NanoAssertMsgf(false, "%s", #x); } while(0)

    const Register Assembler::argRegs[] = { ECX, EDX };
    const Register Assembler::retRegs[] = { EAX, EDX };
    const Register Assembler::savedRegs[] = { EBX, ESI, EDI };

    const static uint8_t max_abi_regs[] = {
        2, /* ABI_FASTCALL */
        1, /* ABI_THISCALL */
        0, /* ABI_STDCALL */
        0  /* ABI_CDECL */
    };


	void Assembler::nInit(AvmCore* core)
	{
		(void) core;
        OSDep::getDate();
	}

	NIns* Assembler::genPrologue()
	{
		/**
		 * Prologue
		 */
		uint32_t stackNeeded = STACK_GRANULARITY * _activation.highwatermark;

		uint32_t stackPushed =
            STACK_GRANULARITY + // returnaddr
            STACK_GRANULARITY; // ebp
		uint32_t aligned = alignUp(stackNeeded + stackPushed, NJ_ALIGN_STACK);
		uint32_t amt = aligned - stackPushed;

		// Reserve stackNeeded bytes, padded
		// to preserve NJ_ALIGN_STACK-byte alignment.
		if (amt) 
		{
			SUBi(SP, amt);
		}

		verbose_only( outputAddr=true; asm_output("[patch entry]"); )
        NIns *patchEntry = _nIns;
		MR(FP, SP); // Establish our own FP.
        PUSHr(FP); // Save caller's FP.

        // align the entry point
        asm_align_code();

		return patchEntry;
	}

    void Assembler::asm_align_code() {
        // todo: the intel optimization guide suggests canonical nop 
        // instructions for sizes from 1..9; use them!
        while(uintptr_t(_nIns) & 7) {
            NOP();
        }
    }

	void Assembler::nFragExit(LInsp guard)
	{
		SideExit *exit = guard->exit();
		bool trees = _frago->core()->config.tree_opt;
        Fragment *frag = exit->target;
        GuardRecord *lr = 0;
		bool destKnown = (frag && frag->fragEntry);
		if (destKnown && !trees)
		{
			// already exists, emit jump now.  no patching required.
			JMP(frag->fragEntry);
            lr = 0;
		}
		else
		{
			// target doesn't exit yet.  emit jump to epilog, and set up to patch later.
			lr = placeGuardRecord(guard);
            JMP_long(_epilogue);
			lr->jmp = _nIns;
		}
		// first restore ESP from EBP, undoing SUBi(SP,amt) from genPrologue
        MR(SP,FP);

        #ifdef NJ_VERBOSE
        if (_frago->core()->config.show_stats) {
			// load EDX (arg1) with Fragment *fromFrag, target fragment
			// will make use of this when calling fragenter().
            int fromfrag = int((Fragment*)_thisfrag);
            LDi(argRegs[1], fromfrag);
        }
        #endif

		// return value is GuardRecord*
        LDi(EAX, int(lr));
	}

    NIns *Assembler::genEpilogue()
    {
        RET();
        POPr(FP); // Restore caller's FP.
        MR(SP,FP); // pop the stack frame
        return  _nIns;
    }
	
	void Assembler::asm_call(LInsp ins)
	{
        const CallInfo* call = ins->callInfo();
		// must be signed, not unsigned
		uint32_t iargs = call->count_iargs();
		int32_t fargs = call->count_args() - iargs;

        bool imt = call->isInterface();
        if (imt) {
			// iid arg is passed via register
            iargs --;
		}

		bool indirect = call->isIndirect();
		if (indirect) {
			// target arg isn't pushed, its consumed in the call
			iargs --;
		}

        uint32_t max_regs = max_abi_regs[call->_abi];
        if (max_regs > iargs)
            max_regs = iargs;

        int32_t istack = iargs-max_regs;  // first 2 4B args are in registers
        int32_t extra = 0;
		const int32_t pushsize = 4*istack + 8*fargs; // actual stack space used

#if _MSC_VER
        // msc is slack, and MIR doesn't do anything extra, so lets use this
        // call-site alignment to at least have code size parity with MIR.
        uint32_t align = 4;//NJ_ALIGN_STACK;
#else
        uint32_t align = NJ_ALIGN_STACK;
#endif

        if (pushsize) {
		    // stack re-alignment 
		    // only pop our adjustment amount since callee pops args in FASTCALL mode
		    extra = alignUp(pushsize, align) - pushsize;
            if (call->_abi == ABI_CDECL) {
				// with CDECL only, caller pops args
                ADDi(SP, extra+pushsize);
            } else if (extra > 0) {
				ADDi(SP, extra);
            }
        }

        if (!indirect) {
    		CALL(call);
        }
        else {
            // indirect call.  x86 Calling conventions don't use EAX as an
            // argument, and do use EAX as a return value.  We need a register
            // for the address to call, so we use EAX since it will always be
            // available
            CALLr(call, EAX);
        }

		// make sure fpu stack is empty before call (restoreCallerSaved)
		NanoAssert(_allocator.isFree(FST0));
		// note: this code requires that ref arguments (ARGSIZE_Q)
        // be one of the first two arguments
		// pre-assign registers to the first N 4B args based on the calling convention
		uint32_t n = 0;

        ArgSize sizes[MAXARGS];
        uint32_t argc = call->get_sizes(sizes);
        if (indirect) {
            argc--;
            asm_arg(ARGSIZE_P, ins->arg(argc), EAX);
        }

        if (imt) {
            // interface thunk calling convention: put iid in EDX
            NanoAssert(call->_abi == ABI_CDECL);
            argc--;
            asm_arg(ARGSIZE_P, ins->arg(argc), EDX);
        }

		for(uint32_t i=0; i < argc; i++)
		{
			uint32_t j = argc-i-1;
            ArgSize sz = sizes[j];
            Register r = UnknownReg;
            if (n < max_regs && sz != ARGSIZE_F) { 
		        r = argRegs[n++]; // tell asm_arg what reg to use
            }
            asm_arg(sz, ins->arg(j), r);
		}

		if (extra > 0)
			SUBi(SP, extra);
	}

	void Assembler::nMarkExecute(Page* page, int flags)
	{
		NanoAssert(sizeof(Page) == NJ_PAGE_SIZE);
		#if defined WIN32 || defined WIN64
			DWORD dwIgnore;
			static const DWORD kProtFlags[4] = 
			{
				PAGE_READONLY,			// 0
				PAGE_READWRITE,			// PAGE_WRITE
				PAGE_EXECUTE_READ,		// PAGE_EXEC
				PAGE_EXECUTE_READWRITE	// PAGE_EXEC|PAGE_WRITE
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
				PROT_READ,						// 0
				PROT_READ|PROT_WRITE,			// PAGE_WRITE
				PROT_READ|PROT_EXEC,			// PAGE_EXEC
				PROT_READ|PROT_WRITE|PROT_EXEC	// PAGE_EXEC|PAGE_WRITE
			};
			int prot = kProtFlags[flags & (PAGE_WRITE|PAGE_EXEC)];
			intptr_t addr = (intptr_t)page;
			addr &= ~((uintptr_t)NJ_PAGE_SIZE - 1);
			NanoAssert(addr == (intptr_t)page);
			#if defined SOLARIS
			if (mprotect((char *)addr, NJ_PAGE_SIZE, prot) == -1) 
			#elif defined AVMPLUS_MAC
			task_t task = mach_task_self();
			if (vm_protect(task, addr, NJ_PAGE_SIZE, true, prot) == -1)
			#else
			if (mprotect((void *)addr, NJ_PAGE_SIZE, prot) == -1) 
			#endif
			{
				// todo: we can't abort or assert here, we have to fail gracefully.
				NanoAssertMsg(false, "FATAL ERROR: mprotect(PROT_EXEC) failed\n");
                abort();
            }
        #else
			(void)page;
		#endif
	}
			
	Register Assembler::nRegisterAllocFromSet(int set)
	{
		Register r;
		RegAlloc &regs = _allocator;
	#ifdef WIN32
		_asm
		{
			mov ecx, regs
			bsf eax, set					// i = first bit set
			btr RegAlloc::free[ecx], eax	// free &= ~rmask(i)
			mov r, eax
		}
	#elif defined WIN64
		unsigned long tr, fr;
		_BitScanForward(&tr, set);
		_bittestandreset(&fr, tr);
		regs.free = fr;
		r = tr;
	#else
		asm(
			"bsf	%1, %%eax\n\t"
			"btr	%%eax, %2\n\t"
			"movl	%%eax, %0\n\t"
			: "=m"(r) : "m"(set), "m"(regs.free) : "%eax", "memory" );
	#endif /* WIN32 */
		return r;
	}

	void Assembler::nRegisterResetAll(RegAlloc& a)
	{
		// add scratch registers to our free list for the allocator
		a.clear();
		a.used = 0;
		a.free = SavedRegs | ScratchRegs;
        if (!config.sse2)
            a.free &= ~XmmRegs;
		debug_only( a.managed = a.free; )
	}

	void Assembler::nPatchBranch(NIns* branch, NIns* location)
	{
		intptr_t offset = intptr_t(location) - intptr_t(branch);
		if (branch[0] == JMPc)
			*(uint32_t*)&branch[1] = offset - 5;
		else
			*(uint32_t*)&branch[2] = offset - 6;
	}

	RegisterMask Assembler::hint(LIns* i, RegisterMask allow)
	{
		uint32_t op = i->opcode();
		int prefer = allow;
        if (op == LIR_icall) {
			prefer &= rmask(retRegs[0]);
        }
        else if (op == LIR_fcall) {
            prefer &= rmask(FST0);
        }
        else if (op == LIR_param) {
            uint32_t max_regs = max_abi_regs[_thisfrag->lirbuf->abi];
            if (i->imm8() < max_regs)
    			prefer &= rmask(argRegs[i->imm8()]);
        }
        else if (op == LIR_callh || op == LIR_rsh && i->oprnd1()->opcode()==LIR_callh) {
            prefer &= rmask(retRegs[1]);
        }
        else if (i->isCmp()) {
			prefer &= AllowableFlagRegs;
        }
        else if (i->isconst()) {
            prefer &= ScratchRegs;
        }
		return (_allocator.free & prefer) ? prefer : allow;
	}

    void Assembler::asm_qjoin(LIns *ins)
    {
		int d = findMemFor(ins);
		AvmAssert(d);
		LIns* lo = ins->oprnd1();
		LIns* hi = ins->oprnd2();

        Reservation *resv = getresv(ins);
        Register rr = resv->reg;

        if (rr != UnknownReg && (rmask(rr) & FpRegs))
            evict(rr);

        if (hi->isconst())
		{
			STi(FP, d+4, hi->constval());
		}
		else
		{
			Register r = findRegFor(hi, GpRegs);
			ST(FP, d+4, r);
		}

        if (lo->isconst())
		{
			STi(FP, d, lo->constval());
		}
		else
		{
			// okay if r gets recycled.
			Register r = findRegFor(lo, GpRegs);
			ST(FP, d, r);
		}

        freeRsrcOf(ins, false);	// if we had a reg in use, emit a ST to flush it to mem
    }

	void Assembler::asm_load(int d, Register r)
	{
		if (rmask(r) & FpRegs)
		{
			if (rmask(r) & XmmRegs) {
				SSE_LDQ(r, d, FP);
			} else {
				FLDQ(d, FP); 
			}
		}
		else
		{
			LD(r, d, FP);
		}
	}
	
	void Assembler::asm_restore(LInsp i, Reservation *resv, Register r)
	{
        if (i->isop(LIR_alloc)) {
			verbose_only( if (_verbose) { outputForEOL("  <= remat %s size %d", _thisfrag->lirbuf->names->formatRef(i), i->size()); } )
            LEA(r, disp(resv), FP);
        }
        else if (i->isconst()) {
            if (!resv->arIndex) {
                reserveFree(i);
            }
            LDi(r, i->constval());
        }
        else {
            int d = findMemFor(i);
			verbose_only( if (_verbose) { outputForEOL("  <= restore %s", _thisfrag->lirbuf->names->formatRef(i)); } )
			asm_load(d,r);
        }
	}

    void Assembler::asm_store32(LIns *value, int dr, LIns *base)
    {
        if (value->isconst())
        {
			Register rb = getBaseReg(base, dr, GpRegs);
            int c = value->constval();
			STi(rb, dr, c);
        }
        else
        {
		    // make sure what is in a register
		    Reservation *rA, *rB;
            Register ra, rb;
            if (base->isop(LIR_alloc)) {
                rb = FP;
                dr += findMemFor(base);
                ra = findRegFor(value, GpRegs);
            } else if (base->isconst()) {
                // absolute address
                dr += base->constval();
                ra = findRegFor(value, GpRegs);
                rb = UnknownReg;
            } else {
    		    findRegFor2(GpRegs, value, rA, base, rB);
		        ra = rA->reg;
		        rb = rB->reg;
            }
		    ST(rb, dr, ra);
        }
    }

	void Assembler::asm_spill(Register rr, int d, bool pop, bool quad)
	{
		(void)quad;
		if (d)
		{
			// save to spill location
            if (rmask(rr) & FpRegs)
			{
                if (rmask(rr) & XmmRegs) {
                    SSE_STQ(d, FP, rr);
                } else {
					FSTQ((pop?1:0), d, FP);
                }
			}
			else
			{
				ST(FP, d, rr);
			}
		}
		else if (pop && (rmask(rr) & x87Regs))
		{
			// pop the fpu result since it isn't used
			FSTP(FST0);
		}
	}

	void Assembler::asm_load64(LInsp ins)
	{
		LIns* base = ins->oprnd1();
		int db = ins->oprnd2()->constval();
		Reservation *resv = getresv(ins);
		Register rr = resv->reg;

		if (rr != UnknownReg && rmask(rr) & XmmRegs)
		{
			freeRsrcOf(ins, false);
			Register rb = getBaseReg(base, db, GpRegs);
			SSE_LDQ(rr, db, rb);
		}
		else
		{
			int dr = disp(resv);
			Register rb;
            if (base->isop(LIR_alloc)) {
                rb = FP;
                db += findMemFor(base);
            } else {
                rb = findRegFor(base, GpRegs);
            }
			resv->reg = UnknownReg;

			// don't use an fpu reg to simply load & store the value.
			if (dr)
				asm_mmq(FP, dr, rb, db);

			freeRsrcOf(ins, false);

			if (rr != UnknownReg)
			{
				NanoAssert(rmask(rr)&FpRegs);
				_allocator.retire(rr);
				FLDQ(db, rb);
			}
		}
	}

	void Assembler::asm_store64(LInsp value, int dr, LInsp base)
	{
		if (value->isconstq())
		{
			// if a constant 64-bit value just store it now rather than
			// generating a pointless store/load/store sequence
			Register rb;
            if (base->isop(LIR_alloc)) {
                rb = FP;
                dr += findMemFor(base);
            } else {
                rb = findRegFor(base, GpRegs);
            }
			const int32_t* p = (const int32_t*) (value-2);
			STi(rb, dr+4, p[1]);
			STi(rb, dr, p[0]);
            return;
		}

        if (value->isop(LIR_ldq) || value->isop(LIR_ldqc) || value->isop(LIR_qjoin))
		{
			// value is 64bit struct or int64_t, or maybe a double.
			// it may be live in an FPU reg.  Either way, don't
			// put it in an FPU reg just to load & store it.

			// a) if we know it's not a double, this is right.
			// b) if we guarded that its a double, this store could be on
			// the side exit, copying a non-double.
			// c) maybe its a double just being stored.  oh well.

			if (config.sse2) {
                Register rv = findRegFor(value, XmmRegs);
		Register rb;
		if (base->isop(LIR_alloc)) {
		    rb = FP;
		    dr += findMemFor(base);
		} else {
		    rb = findRegFor(base, GpRegs);
		}
                SSE_STQ(dr, rb, rv);
				return;
            }

			int da = findMemFor(value);
		    Register rb;
		    if (base->isop(LIR_alloc)) {
					rb = FP;
					dr += findMemFor(base);
		    } else {
					rb = findRegFor(base, GpRegs);
		    }
		    asm_mmq(rb, dr, FP, da);
            return;
		}

		Register rb;
		if (base->isop(LIR_alloc)) {
		    rb = FP;
		    dr += findMemFor(base);
		} else {
		    rb = findRegFor(base, GpRegs);
		}

		// if value already in a reg, use that, otherwise
		// try to get it into XMM regs before FPU regs.
		Reservation* rA = getresv(value);
		Register rv;
		int pop = !rA || rA->reg==UnknownReg;
		if (pop) {
		    rv = findRegFor(value, config.sse2 ? XmmRegs : FpRegs);
		} else {
		    rv = rA->reg;
		}

		if (rmask(rv) & XmmRegs) {
            SSE_STQ(dr, rb, rv);
		} else {
			FSTQ(pop, dr, rb);
		}
	}

    /**
     * copy 64 bits: (rd+dd) <- (rs+ds)
     */
    void Assembler::asm_mmq(Register rd, int dd, Register rs, int ds)
    {
        // value is either a 64bit struct or maybe a float
        // that isn't live in an FPU reg.  Either way, don't
        // put it in an FPU reg just to load & store it.
        if (config.sse2)
        {
            // use SSE to load+store 64bits
            Register t = registerAlloc(XmmRegs);
            _allocator.addFree(t);
            SSE_STQ(dd, rd, t);
            SSE_LDQ(t, ds, rs);
        }
        else
        {
            // get a scratch reg
            Register t = registerAlloc(GpRegs & ~(rmask(rd)|rmask(rs)));
            _allocator.addFree(t);
            ST(rd, dd+4, t);
            LD(t, ds+4, rs);
            ST(rd, dd, t);
            LD(t, ds, rs);
        }
    }

	NIns* Assembler::asm_branch(bool branchOnFalse, LInsp cond, NIns* targ)
	{
		NIns* at = 0;
		LOpcode condop = cond->opcode();
		NanoAssert(cond->isCond());
		if (condop >= LIR_feq && condop <= LIR_fge)
		{
			return asm_jmpcc(branchOnFalse, cond, targ);
		}
		// produce the branch
		if (branchOnFalse)
		{
			if (condop == LIR_eq)
				JNE(targ);
			else if (condop == LIR_ov)
				JNO(targ);
			else if (condop == LIR_cs)
				JNC(targ);
			else if (condop == LIR_lt)
				JNL(targ);
			else if (condop == LIR_le)
				JNLE(targ);
			else if (condop == LIR_gt)
				JNG(targ);
			else if (condop == LIR_ge)
				JNGE(targ);
			else if (condop == LIR_ult)
				JNB(targ);
			else if (condop == LIR_ule)
				JNBE(targ);
			else if (condop == LIR_ugt)
				JNA(targ);
			else //if (condop == LIR_uge)
				JNAE(targ);
		}
		else // op == LIR_xt
		{
			if (condop == LIR_eq)
				JE(targ);
			else if (condop == LIR_ov)
				JO(targ);
			else if (condop == LIR_cs)
				JC(targ);
			else if (condop == LIR_lt)
				JL(targ);
			else if (condop == LIR_le)
				JLE(targ);
			else if (condop == LIR_gt)
				JG(targ);
			else if (condop == LIR_ge)
				JGE(targ);
			else if (condop == LIR_ult)
				JB(targ);
			else if (condop == LIR_ule)
				JBE(targ);
			else if (condop == LIR_ugt)
				JA(targ);
			else //if (condop == LIR_uge)
				JAE(targ);
		}
		at = _nIns;
		asm_cmp(cond);
		return at;
	}

	void Assembler::asm_cmp(LIns *cond)
	{
        LOpcode condop = cond->opcode();
        
        // LIR_ov and LIR_cs recycle the flags set by arithmetic ops
        if ((condop == LIR_ov) || (condop == LIR_cs))
            return;
        
        LInsp lhs = cond->oprnd1();
		LInsp rhs = cond->oprnd2();
		Reservation *rA, *rB;

		NanoAssert((!lhs->isQuad() && !rhs->isQuad()) || (lhs->isQuad() && rhs->isQuad()));

		// Not supported yet.
#if !defined NANOJIT_64BIT
		NanoAssert(!lhs->isQuad() && !rhs->isQuad());
#endif

		// ready to issue the compare
		if (rhs->isconst())
		{
			int c = rhs->constval();
			if (c == 0 && cond->isop(LIR_eq)) {
				Register r = findRegFor(lhs, GpRegs);
				if (rhs->isQuad()) {
#if defined NANOJIT_64BIT
					TESTQ(r, r);
#endif
				} else {
					TEST(r,r);
				}
			// No 64-bit immediates so fall-back to below
			}
			else if (!rhs->isQuad()) {
				Register r = getBaseReg(lhs, c, GpRegs);
				CMPi(r, c);
			}
		}
		else
		{
			findRegFor2(GpRegs, lhs, rA, rhs, rB);
			Register ra = rA->reg;
			Register rb = rB->reg;
			if (rhs->isQuad()) {
#if defined NANOJIT_64BIT
				CMPQ(ra, rb);
#endif
			} else {
				CMP(ra, rb);
			}
		}
	}

	void Assembler::asm_loop(LInsp ins, NInsList& loopJumps)
	{
		(void)ins;
		JMP_long_placeholder(); // jump to SOT	
		verbose_only( if (_verbose && _outputCache) { _outputCache->removeLast(); outputf("         jmp   SOT"); } );
		
		loopJumps.add(_nIns);

		#ifdef NJ_VERBOSE
		// branching from this frag to ourself.
		if (_frago->core()->config.show_stats)
			LDi(argRegs[1], int((Fragment*)_thisfrag));
		#endif

		assignSavedParams();

		// restore first parameter, the only one we use
		LInsp state = _thisfrag->lirbuf->state;
		findSpecificRegFor(state, argRegs[state->imm8()]); 
	}	

	void Assembler::asm_fcond(LInsp ins)
	{
		// only want certain regs 
		Register r = prepResultReg(ins, AllowableFlagRegs);
		asm_setcc(r, ins);
#ifdef NJ_ARM_VFP
		SETE(r);
#else
		// SETcc only sets low 8 bits, so extend 
		MOVZX8(r,r);
		SETNP(r);
#endif
		asm_fcmp(ins);
	}
				
	void Assembler::asm_cond(LInsp ins)
	{
		// only want certain regs 
		LOpcode op = ins->opcode();			
		Register r = prepResultReg(ins, AllowableFlagRegs);
		// SETcc only sets low 8 bits, so extend 
		MOVZX8(r,r);
		if (op == LIR_eq)
			SETE(r);
		else if (op == LIR_ov)
			SETO(r);
		else if (op == LIR_cs)
			SETC(r);
		else if (op == LIR_lt)
			SETL(r);
		else if (op == LIR_le)
			SETLE(r);
		else if (op == LIR_gt)
			SETG(r);
		else if (op == LIR_ge)
			SETGE(r);
		else if (op == LIR_ult)
			SETB(r);
		else if (op == LIR_ule)
			SETBE(r);
		else if (op == LIR_ugt)
			SETA(r);
		else // if (op == LIR_uge)
			SETAE(r);
		asm_cmp(ins);
	}
	
	void Assembler::asm_arith(LInsp ins)
	{
		LOpcode op = ins->opcode();			
		LInsp lhs = ins->oprnd1();
		LInsp rhs = ins->oprnd2();

		Register rb = UnknownReg;
		RegisterMask allow = GpRegs;
		bool forceReg = (op == LIR_mul || !rhs->isconst());

#ifdef NANOJIT_ARM
		// Arm can't do an immediate op with immediates
		// outside of +/-255 (for AND) r outside of
		// 0..255 for others.
		if (!forceReg)
		{
			if (rhs->isconst() && !isU8(rhs->constval()))
				forceReg = true;
		}
#endif

		if (lhs != rhs && forceReg)
		{
			if ((rb = asm_binop_rhs_reg(ins)) == UnknownReg) {
				rb = findRegFor(rhs, allow);
			}
			allow &= ~rmask(rb);
		}
		else if ((op == LIR_add||op == LIR_addp) && lhs->isop(LIR_alloc) && rhs->isconst()) {
			// add alloc+const, use lea
			Register rr = prepResultReg(ins, allow);
			int d = findMemFor(lhs) + rhs->constval();
			LEA(rr, d, FP);
		}

		Register rr = prepResultReg(ins, allow);
		Reservation* rA = getresv(lhs);
		Register ra;
		// if this is last use of lhs in reg, we can re-use result reg
		if (rA == 0 || (ra = rA->reg) == UnknownReg)
			ra = findSpecificRegFor(lhs, rr);
		// else, rA already has a register assigned.

		if (forceReg)
		{
			if (lhs == rhs)
				rb = ra;

			if (op == LIR_add || op == LIR_addp)
				ADD(rr, rb);
			else if (op == LIR_sub)
				SUB(rr, rb);
			else if (op == LIR_mul)
				MUL(rr, rb);
			else if (op == LIR_and)
				AND(rr, rb);
			else if (op == LIR_or)
				OR(rr, rb);
			else if (op == LIR_xor)
				XOR(rr, rb);
			else if (op == LIR_lsh)
				SHL(rr, rb);
			else if (op == LIR_rsh)
				SAR(rr, rb);
			else if (op == LIR_ush)
				SHR(rr, rb);
			else
				NanoAssertMsg(0, "Unsupported");
		}
		else
		{
			int c = rhs->constval();
			if (op == LIR_add || op == LIR_addp) {
#ifdef NANOJIT_IA32_TODO
				if (ra != rr) {
					// this doesn't set cc's, only use it when cc's not required.
					LEA(rr, c, ra);
					ra = rr; // suppress mov
				} else
#endif
				{
					ADDi(rr, c); 
				}
			} else if (op == LIR_sub) {
				if (ra != rr) {
					LEA(rr, -c, ra);
					ra = rr;
				} else
				{
					SUBi(rr, c); 
				}
			} else if (op == LIR_and)
				ANDi(rr, c);
			else if (op == LIR_or)
				ORi(rr, c);
			else if (op == LIR_xor)
				XORi(rr, c);
			else if (op == LIR_lsh)
				SHLi(rr, c);
			else if (op == LIR_rsh)
				SARi(rr, c);
			else if (op == LIR_ush)
				SHRi(rr, c);
			else
				NanoAssertMsg(0, "Unsupported");
		}

		if ( rr != ra ) 
			MR(rr,ra);
	}
	
	void Assembler::asm_neg_not(LInsp ins)
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

		if (op == LIR_not)
			NOT(rr); 
		else
			NEG(rr); 

		if ( rr != ra ) 
			MR(rr,ra); 
	}
				
	void Assembler::asm_ld(LInsp ins)
	{
		LOpcode op = ins->opcode();			
		LIns* base = ins->oprnd1();
		LIns* disp = ins->oprnd2();
		Register rr = prepResultReg(ins, GpRegs);
		int d = disp->constval();
		Register ra = getBaseReg(base, d, GpRegs);
		if (op == LIR_ldcb)
			LD8Z(rr, d, ra);
		else
			LD(rr, d, ra); 
	}

	void Assembler::asm_cmov(LInsp ins)
	{
		LOpcode op = ins->opcode();			
		LIns* condval = ins->oprnd1();
		NanoAssert(condval->isCmp());

		LIns* values = ins->oprnd2();

		NanoAssert(values->opcode() == LIR_2);
		LIns* iftrue = values->oprnd1();
		LIns* iffalse = values->oprnd2();

		NanoAssert(op == LIR_qcmov || (!iftrue->isQuad() && !iffalse->isQuad()));
		
		const Register rr = prepResultReg(ins, GpRegs);

		// this code assumes that neither LD nor MR nor MRcc set any of the condition flags.
		// (This is true on Intel, is it true on all architectures?)
		const Register iffalsereg = findRegFor(iffalse, GpRegs & ~rmask(rr));
		if (op == LIR_cmov) {
			switch (condval->opcode())
			{
				// note that these are all opposites...
				case LIR_eq:	MRNE(rr, iffalsereg);	break;
				case LIR_ov:    MRNO(rr, iffalsereg);   break;
				case LIR_cs:    MRNC(rr, iffalsereg);   break;
				case LIR_lt:	MRGE(rr, iffalsereg);	break;
				case LIR_le:	MRG(rr, iffalsereg);	break;
				case LIR_gt:	MRLE(rr, iffalsereg);	break;
				case LIR_ge:	MRL(rr, iffalsereg);	break;
				case LIR_ult:	MRAE(rr, iffalsereg);	break;
				case LIR_ule:	MRA(rr, iffalsereg);	break;
				case LIR_ugt:	MRBE(rr, iffalsereg);	break;
				case LIR_uge:	MRB(rr, iffalsereg);	break;
				debug_only( default: NanoAssert(0); break; )
			}
		} else if (op == LIR_qcmov) {
#if !defined NANOJIT_64BIT
			NanoAssert(0);
#else
			switch (condval->opcode())
			{
				// note that these are all opposites...
				case LIR_eq:	MRQNE(rr, iffalsereg);	break;
				case LIR_ov:    MRQNO(rr, iffalsereg);   break;
				case LIR_cs:    MRQNC(rr, iffalsereg);   break;
				case LIR_lt:	MRQGE(rr, iffalsereg);	break;
				case LIR_le:	MRQG(rr, iffalsereg);	break;
				case LIR_gt:	MRQLE(rr, iffalsereg);	break;
				case LIR_ge:	MRQL(rr, iffalsereg);	break;
				case LIR_ult:	MRQAE(rr, iffalsereg);	break;
				case LIR_ule:	MRQA(rr, iffalsereg);	break;
				case LIR_ugt:	MRQBE(rr, iffalsereg);	break;
				case LIR_uge:	MRQB(rr, iffalsereg);	break;
				debug_only( default: NanoAssert(0); break; )
			}
#endif
		}
		/*const Register iftruereg =*/ findSpecificRegFor(iftrue, rr);
		asm_cmp(condval);
	}
				
	void Assembler::asm_qhi(LInsp ins)
	{
		Register rr = prepResultReg(ins, GpRegs);
		LIns *q = ins->oprnd1();
		int d = findMemFor(q);
		LD(rr, d+4, FP);
	}

	void Assembler::asm_param(LInsp ins)
	{
		uint32_t a = ins->imm8();
		uint32_t kind = ins->imm8b();
		if (kind == 0) {
			// ordinary param
			AbiKind abi = _thisfrag->lirbuf->abi;
			uint32_t abi_regcount = abi == ABI_FASTCALL ? 2 : abi == ABI_THISCALL ? 1 : 0;
			if (a < abi_regcount) {
				// incoming arg in register
				prepResultReg(ins, rmask(argRegs[a]));
			} else {
				// incoming arg is on stack, and EBP points nearby (see genPrologue)
				Register r = prepResultReg(ins, GpRegs);
				int d = (a - abi_regcount) * sizeof(intptr_t) + 8;
				LD(r, d, FP); 
			}
		}
		else {
			// saved param
			prepResultReg(ins, rmask(savedRegs[a]));
		}
	}

	void Assembler::asm_short(LInsp ins)
	{
		Register rr = prepResultReg(ins, GpRegs);
		int32_t val = ins->imm16();
		if (val == 0)
			XOR(rr,rr);
		else
			LDi(rr, val);
	}

	void Assembler::asm_int(LInsp ins)
	{
		Register rr = prepResultReg(ins, GpRegs);
		int32_t val = ins->imm32();
		if (val == 0)
			XOR(rr,rr);
		else
			LDi(rr, val);
	}

	void Assembler::asm_quad(LInsp ins)
	{
    	Reservation *rR = getresv(ins);
		Register rr = rR->reg;
		if (rr != UnknownReg)
		{
			// @todo -- add special-cases for 0 and 1
			_allocator.retire(rr);
			rR->reg = UnknownReg;
			NanoAssert((rmask(rr) & FpRegs) != 0);

			const double d = ins->constvalf();
            const uint64_t q = ins->constvalq();
			if (rmask(rr) & XmmRegs) {
				if (q == 0.0) {
                    // test (int64)0 since -0.0 == 0.0
					SSE_XORPDr(rr, rr);
				} else if (d == 1.0) {
					// 1.0 is extremely frequent and worth special-casing!
					static const double k_ONE = 1.0;
					LDSDm(rr, &k_ONE);
				} else {
					findMemFor(ins);
					const int d = disp(rR);
					SSE_LDQ(rr, d, FP);
				}
			} else {
				if (q == 0.0) {
                    // test (int64)0 since -0.0 == 0.0
					FLDZ();
				} else if (d == 1.0) {
					FLD1();
				} else {
					findMemFor(ins);
					int d = disp(rR);
					FLDQ(d,FP);
				}
			}
		}

		// @todo, if we used xor, ldsd, fldz, etc above, we don't need mem here
		int d = disp(rR);
		freeRsrcOf(ins, false);
		if (d)
		{
			const int32_t* p = (const int32_t*) (ins-2);
			STi(FP,d+4,p[1]);
			STi(FP,d,p[0]);
		}
	}
	
	void Assembler::asm_qlo(LInsp ins)
	{
		LIns *q = ins->oprnd1();

		if (!config.sse2)
		{
			Register rr = prepResultReg(ins, GpRegs);
			int d = findMemFor(q);
			LD(rr, d, FP);
		}
		else
		{
			Reservation *resv = getresv(ins);
			Register rr = resv->reg;
			if (rr == UnknownReg) {
				// store quad in spill loc
				int d = disp(resv);
				freeRsrcOf(ins, false);
				Register qr = findRegFor(q, XmmRegs);
				SSE_MOVDm(d, FP, qr);
			} else {
				freeRsrcOf(ins, false);
				Register qr = findRegFor(q, XmmRegs);
				SSE_MOVD(rr,qr);
			}
		}
	}

	void Assembler::asm_fneg(LInsp ins)
	{
		if (config.sse2)
		{
			LIns *lhs = ins->oprnd1();

			Register rr = prepResultReg(ins, XmmRegs);
			Reservation *rA = getresv(lhs);
			Register ra;

			// if this is last use of lhs in reg, we can re-use result reg
			if (rA == 0 || (ra = rA->reg) == UnknownReg) {
				ra = findSpecificRegFor(lhs, rr);
			} else if ((rmask(ra) & XmmRegs) == 0) {
				// it's possible that an earlier instruction has put this in
				// an x87 FPU register.  If so, ask for a new register.
				ra = findRegFor(lhs, XmmRegs);
			}
			// else, rA already has an XMM register assigned.

#if defined __SUNPRO_CC
			// from Sun Studio C++ Readme: #pragma align inside namespace requires mangled names
			static uint32_t temp[] = {0, 0, 0, 0, 0, 0, 0};
			static uint32_t *negateMask = (uint32_t *)alignUp(temp, 16);
			negateMask[1] = 0x80000000;
#else
			static const AVMPLUS_ALIGN16(uint32_t) negateMask[] = {0,0x80000000,0,0};
#endif
			SSE_XORPD(rr, negateMask);

			if (rr != ra)
				SSE_MOVSD(rr, ra);
		}
		else
		{
			Register rr = prepResultReg(ins, FpRegs);

			LIns* lhs = ins->oprnd1();

			// lhs into reg, prefer same reg as result
			Reservation* rA = getresv(lhs);
			// if this is last use of lhs in reg, we can re-use result reg
			if (rA == 0 || rA->reg == UnknownReg)
				findSpecificRegFor(lhs, rr);
			// else, rA already has a different reg assigned

			NanoAssert(getresv(lhs)!=0 && getresv(lhs)->reg==FST0);
			// assume that the lhs is in ST(0) and rhs is on stack
			FCHS();

			// if we had more than one fpu reg, this is where
			// we would move ra into rr if rr != ra.
		}
	}

    void Assembler::asm_arg(ArgSize sz, LInsp p, Register r)
    {
        if (sz == ARGSIZE_Q) 
        {
			// ref arg - use lea
			if (r != UnknownReg)
			{
				// arg in specific reg
				int da = findMemFor(p);
				LEA(r, da, FP);
			}
			else
			{
				NanoAssert(0); // not supported
			}
		}
        else if (sz == ARGSIZE_I || sz == ARGSIZE_U)
		{
			if (r != UnknownReg) {
				// arg goes in specific register
                if (p->isconst()) {
					LDi(r, p->constval());
                } else {
            		Reservation* rA = getresv(p);
                    if (rA) {
                        if (rA->reg == UnknownReg) {
                            // load it into the arg reg
                            int d = findMemFor(p);
                            if (p->isop(LIR_alloc)) {
                                LEA(r, d, FP);
                            } else {
                                LD(r, d, FP);
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
				asm_pusharg(p);
			}
		}
        else
		{
            NanoAssert(sz == ARGSIZE_F);
			asm_farg(p);
		}
    }

	void Assembler::asm_pusharg(LInsp p)
	{
		// arg goes on stack
		Reservation* rA = getresv(p);
		if (rA == 0 && p->isconst())
		{
			// small const we push directly
			PUSHi(p->constval());
		}
		else if (rA == 0 || p->isop(LIR_alloc))
		{
			Register ra = findRegFor(p, GpRegs);
			PUSHr(ra);
		}
		else if (rA->reg == UnknownReg)
		{
			PUSHm(disp(rA), FP);
		}
		else
		{
			PUSHr(rA->reg);
		}
	}

	void Assembler::asm_farg(LInsp p)
	{
        NanoAssert(p->isQuad());
		Register r = findRegFor(p, FpRegs);
		if (rmask(r) & XmmRegs) {
			SSE_STQ(0, SP, r); 
		} else {
			FSTPQ(0, SP);
		}
        SUBi(ESP,8);
		//PUSHr(ECX); // 2*pushr is smaller than sub
		//PUSHr(ECX);
	}

	void Assembler::asm_fop(LInsp ins)
	{
		LOpcode op = ins->opcode();
		if (config.sse2)
		{
			LIns *lhs = ins->oprnd1();
			LIns *rhs = ins->oprnd2();

			RegisterMask allow = XmmRegs;
			Register rb = UnknownReg;
			if (lhs != rhs) {
				rb = findRegFor(rhs,allow);
				allow &= ~rmask(rb);
			}

			Register rr = prepResultReg(ins, allow);
			Reservation *rA = getresv(lhs);
			Register ra;

			// if this is last use of lhs in reg, we can re-use result reg
			if (rA == 0 || (ra = rA->reg) == UnknownReg) {
				ra = findSpecificRegFor(lhs, rr);
			} else if ((rmask(ra) & XmmRegs) == 0) {
				// It's possible that an earlier instruction has put lhs
				// into an x87 FPU register. If so, ask for a new register.
				ra = findRegFor(lhs, XmmRegs);
			}
            else {
    			// rA already has a register assigned but maybe not from the allow set
                ra = findRegFor(lhs, allow);
            }

			if (lhs == rhs)
				rb = ra;

			if (op == LIR_fadd)
				SSE_ADDSD(rr, rb);
			else if (op == LIR_fsub)
				SSE_SUBSD(rr, rb);
			else if (op == LIR_fmul)
				SSE_MULSD(rr, rb);
			else //if (op == LIR_fdiv)
				SSE_DIVSD(rr, rb);

			if (rr != ra)
				SSE_MOVSD(rr, ra);
		}
		else
		{
			// we swap lhs/rhs on purpose here, works out better
			// if you only have one fpu reg.  use divr/subr.
			LIns* rhs = ins->oprnd1();
			LIns* lhs = ins->oprnd2();
			Register rr = prepResultReg(ins, rmask(FST0));

			// make sure rhs is in memory
			int db = findMemFor(rhs);

			// lhs into reg, prefer same reg as result
			Reservation* rA = getresv(lhs);
			// last use of lhs in reg, can reuse rr
			if (rA == 0 || rA->reg == UnknownReg)
				findSpecificRegFor(lhs, rr);
			// else, rA already has a different reg assigned

			NanoAssert(getresv(lhs)!=0 && getresv(lhs)->reg==FST0);
			// assume that the lhs is in ST(0) and rhs is on stack
			if (op == LIR_fadd)
				{ FADD(db, FP); }
			else if (op == LIR_fsub)
				{ FSUBR(db, FP); }
			else if (op == LIR_fmul)
				{ FMUL(db, FP); }
			else if (op == LIR_fdiv)
				{ FDIVR(db, FP); }
		}
	}

	void Assembler::asm_i2f(LInsp ins)
	{
		// where our result goes
		Register rr = prepResultReg(ins, FpRegs);
		if (rmask(rr) & XmmRegs) 
		{
			// todo support int value in memory
			Register gr = findRegFor(ins->oprnd1(), GpRegs);
			SSE_CVTSI2SD(rr, gr);
            SSE_XORPDr(rr,rr);  // zero rr to ensure no dependency stalls
		} 
		else 
		{
			int d = findMemFor(ins->oprnd1());
			FILD(d, FP);
		}
	}

	Register Assembler::asm_prep_fcall(Reservation *rR, LInsp ins)
	{
		if (rR) {
    		Register rr;
			if ((rr=rR->reg) != UnknownReg && (rmask(rr) & XmmRegs))
				evict(rr);
		}
		return prepResultReg(ins, rmask(FST0));
	}

	void Assembler::asm_u2f(LInsp ins)
	{
		// where our result goes
		Register rr = prepResultReg(ins, FpRegs);
		if (rmask(rr) & XmmRegs) 
		{
			// don't call findRegFor, we want a reg we can stomp on for a very short time,
			// not a reg that will continue to be associated with the LIns
			Register gr = registerAlloc(GpRegs);

			// technique inspired by gcc disassembly 
			// Edwin explains it:
			//
			// gr is 0..2^32-1
			//
			//	   sub gr,0x80000000
			//
			// now gr is -2^31..2^31-1, i.e. the range of int, but not the same value
			// as before
			//
			//	   cvtsi2sd rr,gr
			//
			// rr is now a double with the int value range
			//
			//     addsd rr, 2147483648.0
			//
			// adding back double(0x80000000) makes the range 0..2^32-1.  
			
			static const double k_NEGONE = 2147483648.0;
			SSE_ADDSDm(rr, &k_NEGONE);

			SSE_CVTSI2SD(rr, gr);
            SSE_XORPDr(rr,rr);  // zero rr to ensure no dependency stalls

			Reservation* resv = getresv(ins->oprnd1());
			Register xr;
			if (resv && (xr = resv->reg) != UnknownReg && (rmask(xr) & GpRegs))
			{
				LEA(gr, 0x80000000, xr);
			}
			else
			{
				const int d = findMemFor(ins->oprnd1());
				SUBi(gr, 0x80000000);
				LD(gr, d, FP);
			}
			
			// ok, we're done with it
			_allocator.addFree(gr); 
		} 
		else 
		{
            const int disp = -8;
            const Register base = SP;
			Register gr = findRegFor(ins->oprnd1(), GpRegs);
			NanoAssert(rr == FST0);
			FILDQ(disp, base);
			STi(base, disp+4, 0);	// high 32 bits = 0
			ST(base, disp, gr);		// low 32 bits = unsigned value
		}
	}

	void Assembler::asm_nongp_copy(Register r, Register s)
	{
		if ((rmask(r) & XmmRegs) && (rmask(s) & XmmRegs)) {
			SSE_MOVSD(r, s);
		} else if ((rmask(r) & GpRegs) && (rmask(s) & XmmRegs)) {
			SSE_MOVD(r, s);
		} else {
			if (rmask(r) & XmmRegs) {
				// x87 -> xmm
				NanoAssertMsg(false, "Should not move data from GPR to XMM");
			} else {
				// xmm -> x87
				NanoAssertMsg(false, "Should not move data from GPR/XMM to x87 FPU");
			}
		}
	}

    NIns * Assembler::asm_jmpcc(bool branchOnFalse, LIns *cond, NIns *targ)
    {
        LOpcode c = cond->opcode();
        if (config.sse2 && c != LIR_feq) {
            LIns *lhs = cond->oprnd1();
            LIns *rhs = cond->oprnd2();
            if (c == LIR_flt) {
                LIns *t = lhs; lhs = rhs; rhs = t;
                c = LIR_fgt;
            }
            else if (c == LIR_fle) {
                LIns *t = lhs; lhs = rhs; rhs = t;
                c = LIR_fge;
            }

            if (c == LIR_fgt) {
                if (branchOnFalse) { JNA(targ); } else { JA(targ); }
            }
            else { // if (c == LIR_fge)
                if (branchOnFalse) { JNAE(targ); } else { JAE(targ); }
            }
            NIns *at = _nIns;
            Reservation *rA, *rB;
            findRegFor2(XmmRegs, lhs, rA, rhs, rB);
            SSE_UCOMISD(rA->reg, rB->reg);
            return at;
        }

    	if (branchOnFalse)
			JP(targ);
		else
			JNP(targ);
		NIns *at = _nIns;
		asm_fcmp(cond);
        return at;
    }

    void Assembler::asm_setcc(Register r, LIns *cond)
    {
        LOpcode c = cond->opcode();
        if (config.sse2 && c != LIR_feq) {
    		MOVZX8(r,r);
            LIns *lhs = cond->oprnd1();
            LIns *rhs = cond->oprnd2();
            if (c == LIR_flt) {
                LIns *t = lhs; lhs = rhs; rhs = t;
                SETA(r);
            }
            else if (c == LIR_fle) {
                LIns *t = lhs; lhs = rhs; rhs = t;
                SETAE(r);
            }
            else if (c == LIR_fgt) {
                SETA(r);
            }
            else { // if (c == LIR_fge)
                SETAE(r);
            }
            Reservation *rA, *rB;
            findRegFor2(XmmRegs, lhs, rA, rhs, rB);
            SSE_UCOMISD(rA->reg, rB->reg);
            return;
        }
		// SETcc only sets low 8 bits, so extend 
		MOVZX8(r,r);
		SETNP(r);
        asm_fcmp(cond);
    }

	void Assembler::asm_fcmp(LIns *cond)
	{
		LOpcode condop = cond->opcode();
		NanoAssert(condop >= LIR_feq && condop <= LIR_fge);
	    LIns* lhs = cond->oprnd1();
	    LIns* rhs = cond->oprnd2();

        int mask;
	    if (condop == LIR_feq)
		    mask = 0x44;
	    else if (condop == LIR_fle)
		    mask = 0x41;
	    else if (condop == LIR_flt)
		    mask = 0x05;
        else if (condop == LIR_fge) {
            // swap, use le
            condop = LIR_fle;
            LIns* t = lhs; lhs = rhs; rhs = t;
            mask = 0x41;
        } else { // if (condop == LIR_fgt)
            // swap, use lt
            condop = LIR_flt;
            LIns* t = lhs; lhs = rhs; rhs = t;
		    mask = 0x05;
        }

        if (config.sse2)
        {
            // UNORDERED:    ZF,PF,CF <- 111;
            // GREATER_THAN: ZF,PF,CF <- 000;
            // LESS_THAN:    ZF,PF,CF <- 001;
            // EQUAL:        ZF,PF,CF <- 100;

            if (condop == LIR_feq && lhs == rhs) {
                // nan check
                Register r = findRegFor(lhs, XmmRegs);
                SSE_UCOMISD(r, r);
            } 
            else {
                evict(EAX);
                TEST_AH(mask);
                LAHF();
                Reservation *rA, *rB;
                findRegFor2(XmmRegs, lhs, rA, rhs, rB);
                SSE_UCOMISD(rA->reg, rB->reg);
            }
        }
        else
        {
            evict(EAX);
            TEST_AH(mask);
		    FNSTSW_AX();
		    NanoAssert(lhs->isQuad() && rhs->isQuad());
		    Reservation *rA;
		    if (lhs != rhs)
		    {
			    // compare two different numbers
			    int d = findMemFor(rhs);
			    rA = getresv(lhs);
			    int pop = !rA || rA->reg == UnknownReg; 
			    findSpecificRegFor(lhs, FST0);
			    // lhs is in ST(0) and rhs is on stack
			    FCOM(pop, d, FP);
		    }
		    else
		    {
			    // compare n to itself, this is a NaN test.
			    rA = getresv(lhs);
			    int pop = !rA || rA->reg == UnknownReg; 
			    findSpecificRegFor(lhs, FST0);
			    // value in ST(0)
			    if (pop)
				    FCOMPP();
			    else
				    FCOMP();
			    FLDr(FST0); // DUP
		    }
        }
	}
	
	NIns* Assembler::asm_adjustBranch(NIns* at, NIns* target)
	{
		NIns *save = _nIns;
		NIns *was = (NIns*)( (intptr_t)*(int32_t*)(at+1)+(intptr_t)(at+5) );
		_nIns = at +5; // +5 is size of JMP
		intptr_t tt = (intptr_t)target - (intptr_t)_nIns;
		IMM32(tt);
		*(--_nIns) = JMPc;
        _nIns = save;
		return was;
	}
	
	void Assembler::nativePageReset()
	{}

	Register Assembler::asm_binop_rhs_reg(LInsp ins)
	{
		LOpcode op = ins->opcode();
		LIns *rhs = ins->oprnd2();

		if (op == LIR_lsh || op == LIR_rsh || op == LIR_ush) {
			return findSpecificRegFor(rhs, ECX);
		}

		return UnknownReg;	
	}

	void Assembler::nativePageSetup()
	{
		if (!_nIns)		 _nIns	   = pageAlloc();
		if (!_nExitIns)  _nExitIns = pageAlloc(true);
	}
	
	// enough room for n bytes
    void Assembler::underrunProtect(int n)
    {
		NanoAssertMsg(n<=LARGEST_UNDERRUN_PROT, "constant LARGEST_UNDERRUN_PROT is too small"); 
        NIns *eip = this->_nIns;
        Page *p = (Page*)pageTop(eip-1);
        NIns *top = (NIns*) &p->code[0];
        if (eip - n < top) {
			_nIns = pageAlloc(_inExit);
            JMP(eip);
        }
    }

    void Assembler::asm_ret(LInsp ins)
    {
        if (_nIns != _epilogue) {
            JMP(_epilogue);
        }
        assignSavedParams();
        LIns *val = ins->oprnd1();
        if (ins->isop(LIR_ret)) {
            findSpecificRegFor(val, retRegs[0]);
        } else {
            findSpecificRegFor(val, FST0);
            fpu_pop();
        }
    }

	void Assembler::asm_promote(LIns *) {
		// i2q or u2q
		TODO(asm_promote);
	}
	
	#endif /* FEATURE_NANOJIT */
}
