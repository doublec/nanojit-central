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


#ifndef __nanojit_Assembler__
#define __nanojit_Assembler__


namespace nanojit
{
    /**
     * Some notes on this Assembler (Emitter).
     *
     *   The class RegAlloc is essentially the register allocator from MIR
     *
     *   The Assembler class parses the LIR instructions starting at any point and converts
     *   them to machine code.  It does the translation using expression trees which are simply
     *   LIR instructions in the stream that have side-effects.  Any other instruction in the
     *   stream is simply ignored.
     *   This approach is interesting in that dead code elimination occurs for 'free', strength
     *   reduction occurs fairly naturally, along with some other optimizations.
     *
     *   A negative is that we require state as we 'push' and 'pop' nodes along the tree.
     *   Also, this is most easily performed using recursion which may not be desirable in
     *   the mobile environment.
     *
     */

    #define STACK_GRANULARITY        sizeof(void *)

    struct AR
    {
        LIns*           entry[ NJ_MAX_STACK_ENTRY ];    /* maps to 4B contiguous locations relative to the frame pointer */
        uint32_t        tos;                            /* current top of stack entry */
        uint32_t        highwatermark;                  /* max tos hit */
        uint32_t        lowwatermark;                   /* we pre-allocate entries from 0 upto this index-1; so dynamic entries are added above this index */
    };

    #ifdef AVMPLUS_WIN32
        #define AVMPLUS_ALIGN16(type) __declspec(align(16)) type
    #else
        #define AVMPLUS_ALIGN16(type) type __attribute__ ((aligned (16)))
    #endif

    struct Stats
    {
        counter_define(steals;)
        counter_define(remats;)
        counter_define(spills;)
        counter_define(native;)
        counter_define(exitnative;)

        int32_t pages;
        NIns* codeStart;
        NIns* codeExitStart;

        DECLARE_PLATFORM_STATS()
#ifdef __GNUC__
        // inexplicably, gnuc gives padding/alignment warnings without this. pacify it.
        bool pad[4];
#endif
    };

    // error codes
    enum AssmError
    {
         None = 0
        ,StackFull
        ,UnknownBranch
    };

    typedef avmplus::List<NIns*, avmplus::LIST_NonGCObjects> NInsList;
    typedef avmplus::SortedMap<LIns*,NIns*,avmplus::LIST_NonGCObjects> InsMap;
    typedef avmplus::SortedMap<NIns*,LIns*,avmplus::LIST_NonGCObjects> NInsMap;

#ifdef VTUNE
    class avmplus::CodegenLIR;
#endif

    class LabelState MMGC_SUBCLASS_DECL
    {
    public:
        RegAlloc regs;
        NIns *addr;
        LabelState(NIns *a, RegAlloc &r) : regs(r), addr(a)
        {}
    };

    class LabelStateMap
    {
        GC *gc;
        avmplus::SortedMap<LIns*, LabelState*, avmplus::LIST_GCObjects> labels;
    public:
        LabelStateMap(GC *gc) : gc(gc), labels(gc)
        {}

        void clear() { labels.clear(); }
        void add(LIns *label, NIns *addr, RegAlloc &regs);
        LabelState *get(LIns *);
    };

    /**
     * Information about the activation record for the method is built up
     * as we generate machine code.  As part of the prologue, we issue
     * a stack adjustment instruction and then later patch the adjustment
     * value.  Temporary values can be placed into the AR as method calls
     * are issued.   Also LIR_alloc instructions will consume space.
     */
    class Assembler MMGC_SUBCLASS_DECL
    {
        friend class VerboseBlockReader;
        public:
            #ifdef NJ_VERBOSE
            static char  outline[8192];
            static char  outlineEOL[512];  // string to be added to the end of the line
            static char* outputAlign(char* s, int col);

            void FASTCALL outputForEOL(const char* format, ...);
            void FASTCALL output(const char* s);
            void FASTCALL outputf(const char* format, ...);
            void FASTCALL output_asm(const char* s);

            bool _verbose, outputAddr, vpad[2];  // if outputAddr=true then next asm instr. will include address in output
            void printActivationState(const char* what);

            StringList* _outputCache;
            #endif

            #ifdef VTUNE
            avmplus::CodegenLIR *cgen;
            #endif

            Assembler(CodeAlloc* codeAlloc, AvmCore* core);
            ~Assembler() {}

            void        assemble(Fragment* frag, NInsList& loopJumps);
            void        endAssembly(Fragment* frag, NInsList& loopJumps);
            void        beginAssembly(Fragment *frag, RegAllocMap* map);
            void        copyRegisters(RegAlloc* copyTo);
            void        releaseRegisters();
            void        patch(GuardRecord *lr);
            void        patch(SideExit *exit);
            AssmError   error() { return _err; }
            void        setError(AssmError e) { _err = e; }
            void        pageReset();

            debug_only ( void       pageValidate(); )

            // support calling out from a fragment ; used to debug the jit
            debug_only( void        resourceConsistencyCheck(); )
            debug_only( void        registerConsistencyCheck(); )

            Stats       _stats;
            int hasLoop;
            CodeList*   codeList;                   // finished blocks of code.

        private:

            void        gen(LirFilter* toCompile, NInsList& loopJumps);
            NIns*       genPrologue();
            NIns*       genEpilogue();

            uint32_t    arReserve(LIns* l);
            void        arFree(uint32_t idx);
            void        arReset();

            Register    registerAlloc(RegisterMask allow);
            void        registerResetAll();
            void        evictRegs(RegisterMask regs);
            void        evictScratchRegs();
            void        intersectRegisterState(RegAlloc& saved);
            void        unionRegisterState(RegAlloc& saved);
            void        assignSaved(RegAlloc &saved, RegisterMask skip);
            LInsp       findVictim(RegAlloc& regs, RegisterMask allow);

            Register    getBaseReg(LIns *i, int &d, RegisterMask allow);
            int         findMemFor(LIns* i);
            Register    findRegFor(LIns* i, RegisterMask allow);
            void        findRegFor2(RegisterMask allow, LIns* ia, Reservation* &ra, LIns *ib, Reservation* &rb);
            Register    findSpecificRegFor(LIns* i, Register w);
            Register    prepResultReg(LIns *i, RegisterMask allow);
            void        freeRsrcOf(LIns *i, bool pop);
            void        evict(Register r);
            RegisterMask hint(LIns*i, RegisterMask allow);
            void        codeAlloc(bool exitPage=false);
            void        internalReset();
            bool        canRemat(LIns*);

            Reservation* getresv(LIns *x) {
                Reservation* r = x->resv();
                return r->used ? r : 0;
            }

            AvmCore             *core;
            DWB(CodeAlloc*)     _codeAlloc;
            GC*                 _gc;
            DWB(Fragment*)      _thisfrag;
            RegAllocMap*        _branchStateMap;

            NIns        *codeStart, *codeEnd;       // current block we're adding code to
            NIns        *exitStart, *exitEnd;       // current block for exit stubs
            NIns*       _nIns;          // current native instruction
            NIns*       _nExitIns;      // current instruction in exit fragment page
            NIns*       _startingIns;   // starting location of code compilation for error handling
            NIns*       _epilogue;
            AssmError   _err;           // 0 = means assemble() appears ok, otherwise it failed
        #if PEDANTIC
            NIns*       pedanticTop;
        #endif

            AR          _activation;
            RegAlloc    _allocator;

            LabelStateMap   _labels;
            NInsMap     _patches;
            bool        _inExit, vpad2[3];
            InsList     pending_lives;

#ifndef NJ_SOFTFLOAT
            void        asm_fcmp(LIns *cond);
            void        asm_setcc(Register res, LIns *cond);
            NIns *      asm_jmpcc(bool brOnFalse, LIns *cond, NIns *target);
#endif
            void        asm_mmq(Register rd, int dd, Register rs, int ds);
            NIns*       asm_exit(LInsp guard);
            NIns*       asm_leave_trace(LInsp guard);
            void        asm_qjoin(LIns *ins);
            void        asm_store32(LIns *val, int d, LIns *base);
            void        asm_store64(LIns *val, int d, LIns *base);
            void        asm_restore(LInsp, Reservation*, Register);
            void        asm_load(int d, Register r);
            void        asm_spilli(LInsp i, Reservation *resv, bool pop);
            void        asm_spill(Register rr, int d, bool pop, bool quad);
            void        asm_load64(LInsp i);
            void        asm_ret(LInsp p);
            void        asm_quad(LInsp i);
            void        asm_loop(LInsp i, NInsList& loopJumps);
            void        asm_fcond(LInsp i);
            void        asm_cond(LInsp i);
            void        asm_arith(LInsp i);
            void        asm_neg_not(LInsp i);
            void        asm_ld(LInsp i);
            void        asm_cmov(LInsp i);
            void        asm_param(LInsp i);
            void        asm_int(LInsp i);
            void        asm_qlo(LInsp i);
            void        asm_qhi(LInsp i);
            void        asm_fneg(LInsp ins);
            void        asm_fop(LInsp ins);
            void        asm_i2f(LInsp ins);
            void        asm_u2f(LInsp ins);
            void        asm_promote(LIns *ins);
            Register    asm_prep_fcall(Reservation *rR, LInsp ins);
            void        asm_nongp_copy(Register r, Register s);
            void        asm_call(LInsp);
            Register    asm_binop_rhs_reg(LInsp ins);
            NIns*       asm_branch(bool branchOnFalse, LInsp cond, NIns* targ);
            void        asm_switch(LIns* ins, NIns* target);
            void        assignSavedRegs();
            void        reserveSavedRegs();
            void        assignParamRegs();
            void        handleLoopCarriedExprs();

            // platform specific implementation (see NativeXXX.cpp file)
            void        nInit(AvmCore *);
            Register    nRegisterAllocFromSet(RegisterMask set);
            void        nRegisterResetAll(RegAlloc& a);
            void        nFrameRestore(RegisterMask rmask);
            static void nPatchBranch(NIns* branch, NIns* location);
            void        nFragExit(LIns* guard);

            // platform specific methods
        public:
            const static Register savedRegs[NumSavedRegs];
            DECLARE_PLATFORM_ASSEMBLER()

        private:
            debug_only( int32_t _fpuStkDepth; )
            debug_only( int32_t _sv_fpuStkDepth; )

            // since we generate backwards the depth is negative
            inline void fpu_push() {
                debug_only( ++_fpuStkDepth; /*char foo[8]= "FPUSTK0"; foo[6]-=_fpuStkDepth; output_asm(foo);*/ NanoAssert(_fpuStkDepth<=0); )
            }
            inline void fpu_pop() {
                debug_only( --_fpuStkDepth; /*char foo[8]= "FPUSTK0"; foo[6]-=_fpuStkDepth; output_asm(foo);*/ NanoAssert(_fpuStkDepth<=0); )
            }
    #ifdef AVMPLUS_PORTING_API
            // these pointers are required to store
            // the address range where code has been
            // modified so we can flush the instruction cache.
            void* _endJit2Addr;
    #endif // AVMPLUS_PORTING_API
            avmplus::Config &config;
    };

    inline int32_t disp(Reservation* r)
    {
        // even on 64bit cpu's, we allocate stack area in 4byte chunks
        return stack_direction(4 * int32_t(r->arIndex));
    }
}
#endif // __nanojit_Assembler__
