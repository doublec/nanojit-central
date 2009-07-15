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

#ifndef __nanojit_LIR__
#define __nanojit_LIR__

#ifdef NANOJIT_64BIT
    #define PTR_SIZE(a,b)  b
#else
    #define PTR_SIZE(a,b)  a
#endif

/**
 * Fundamentally, the arguments to the various operands can be grouped along
 * two dimensions.  One dimension is size: can the arguments fit into a 32-bit
 * register, or not?  The other dimension is whether the argument is an integer
 * (including pointers) or a floating-point value.  In all comments below,
 * "integer" means integer of any size, including 64-bit, unless otherwise
 * specified.  All floating-point values are always 64-bit.  Below, "quad" is
 * used for a 64-bit value that might be either integer or floating-point.
 */
namespace nanojit
{
    #define is_trace_skip_tramp(op) ((op) <= LIR_tramp)

    enum LOpcode
#if defined(_MSC_VER) && _MSC_VER >= 1400
#pragma warning(disable:4480) // nonstandard extension used: specifying underlying type for enum
          : unsigned
#endif
    {
        // flags; upper bits reserved
        LIR64   = 0x40,         // result is double or quad

        // special operations (must be 0..N)
        LIR_start = 0,     // marker for the beginning of LIR, acts as end marker when reading bottom-up
        LIR_nearskip = 1,  // must be LIR_skip-1 and lsb=1 (up to 24bit target)
        LIR_skip = 2,      // skip, target is next 32bit word in LIR
        LIR_neartramp = 3, // must be LIR_tramp-1 and lsb=1 (up to 24bit target)
        LIR_tramp = 4,     // target is next 32bit word in LIR

        // non-pure operations
        LIR_iaddp   = 9,  // int32 add, not CSE enabled intentionally (see below)
        LIR_iparam  = 10, // represents incoming parameter (imm8b=0) or callee-saved register (imm8b=1)
        LIR_st      = 11, // 32-bit store
        LIR_ld      = 12, // 32-bit load
        LIR_ialloc  = 13, // alloc local stack space.  represents pointer to space
        LIR_sti     = 14, // 32-bit store, int8 displacement
        LIR_ret     = 15, // return 32bit value
        LIR_live    = 16, // extend live range of reference
        LIR_icall   = 18, // subroutine call returning a 32-bit GP value (int or pointer)

        // guards
        LIR_loop    = 19, // loop fragment; means jump to LIR_start in current fragment
        LIR_x       = 20, // exit always

        // branches
        LIR_j       = 21, // jump always
        LIR_jt      = 22, // jump if condition true
        LIR_jf      = 23, // jump if condition false
        LIR_label   = 24, // a jump target
        LIR_ji      = 25, // jump indirect
        // operators

        // LIR_feq though LIR_fge must only be used on float arguments.  They
        // return int32 0 or 1.
        LIR_feq     = 26, // floating-point equality [2 float inputs]
        LIR_flt     = 27, // floating-point less than: arg1 < arg2
        LIR_fgt     = 28, // floating-point greater than: arg1 > arg2
        LIR_fle     = 29, // arg1 <= arg2, both floating-point
        LIR_fge     = 30, // arg1 >= arg2, both floating-point

        LIR_cmov    = 31, // conditional move (op1=cond, op2= LIR_2(iftrue,iffalse))
        LIR_short   = 32, // constant 16-bit integer
        LIR_int     = 33, // constant 32-bit integer
        LIR_ldc     = 34, // cse-optimizeable load, otherwise same as LIR_ld
        LIR_2       = 35, // wraps a pair of refs for use in cmov/qcmov - no independent semantics

        // LIR_neg through LIR_ush are all integer operations
        LIR_neg     = 36, // int32 negation [ 1 int32 input / int32 output ]
        LIR_add     = 37, // int32 addition [ 2 operand int32 intputs / int32 output ]
        LIR_sub     = 38, // int32 subtraction
        LIR_mul     = 39, // int32 multiplication (int32 = int32 * int32)
        LIR_callh   = 40, // represents 2nd 32bit register of a register-pair return value
        LIR_and     = 41, // int32 bitwise and
        LIR_or      = 42, // int32 bitwise or
        LIR_xor     = 43, // int32 bitwise xor
        LIR_not     = 44, // int32 bitwise not
        LIR_lsh     = 45, // int32 left shift, rhs bits 5:31 ignored
        LIR_rsh     = 46, // int32 sign-extending right shift, rhs bits 5:31 ignored
        LIR_ush     = 47, // int32 zero-extending right shift, rhs bits 5:31 ignored

        // conditional guards, op^1 to complement.  Only things that are
        // isCond() can be passed to these.
        LIR_xt      = 48, // exit if true   0x30 0011 0000
        LIR_xf      = 49, // exit if false  0x31 0011 0001

        // qlo and qhi take a single quad argument and return its low and high
        // 32 bits respectively as 32-bit integers.
        LIR_qlo     = 50, // low 32bits of 64bit value
        LIR_qhi     = 51, // high 32bits of 64bit value

        LIR_ldcb    = 52, // cse-optimizeable 8-bit load

        LIR_ov      = 53, // overflow condition
        LIR_cs      = 54, // carry set condition
        LIR_eq      = 55, // int32 equality

        // integer (all sizes) relational operators.  op^1 to swap left/right,
        // op^3 to complement.
        LIR_lt      = 56, // signed 32bit <  (0x38 0011 1000)
        LIR_gt      = 57, // signed 32bit >  (0x39 0011 1001)
        LIR_le      = 58, // signed 32bit <= (0x3A 0011 1010)
        LIR_ge      = 59, // signed 32bit >= (0x3B 0011 1011)

        // and the unsigned integer versions
        LIR_ult     = 60, // unsigned 32bit <  (0x3C 0011 1100)
        LIR_ugt     = 61, // unsigned 32bit >  (0x3D 0011 1101)
        LIR_ule     = 62, // unsigned 32bit <= (0x3E 0011 1110)
        LIR_uge     = 63, // unsigned 32bit >= (0x3F 0011 1111)

        // non-64bit ops, but we're out of code space below 64.  used to build
        // symbol tables for output binary, no executable semantics.
        LIR_file    = 1 | LIR64,  // current file, oprnd1 is pointer to filename constant
        LIR_line    = 2 | LIR64,  // current line, oprnd1 is const line #

        /**
         * 64bit operations
         */
        LIR_stq     = LIR_st  | LIR64,  // 64bit store
        LIR_stqi    = LIR_sti | LIR64,  // 64bit store, int8 const displacement
        LIR_fret    = LIR_ret | LIR64,  // return 64bit double value
        LIR_quad    = LIR_int | LIR64,  // 64bit constant value (int64 or double)
        LIR_ldq     = LIR_ld  | LIR64,  // 64bit load
        LIR_ldqc    = LIR_ldc | LIR64,  // 64bit cse-optimizeable load
        LIR_qiand   = 24      | LIR64,  // int64 bitwise and
        LIR_qiadd   = 25      | LIR64,  // int64 add
        LIR_qilsh   = LIR_lsh | LIR64,  // int64 left shift, rhs bits 6:63 ignored
        LIR_qirsh   = LIR_rsh | LIR64,  // int64 signed rightshift
        LIR_qursh   = LIR_ush | LIR64,  // uint64 unsigned rightshift
        LIR_qparam  = LIR_iparam| LIR64, // 64bit param

        LIR_fcall   = LIR_icall | LIR64, // call returning double
        LIR_qcall   = 17        | LIR64, // call returning 64bit gp value (int/pointer)
        LIR_fneg    = LIR_neg   | LIR64, // double negate
        LIR_fadd    = LIR_add   | LIR64, // double add
        LIR_fsub    = LIR_sub   | LIR64, // double subtract
        LIR_fmul    = LIR_mul   | LIR64, // double multiply
        LIR_fdiv    = 40        | LIR64, // double divide
        LIR_qcmov   = LIR_cmov  | LIR64, // 64bit conditional mov

        LIR_qjoin   = 41 | LIR64, // int64 = int32<<32 | int32 (form quad from 2 int32)
        LIR_i2f     = 48 | LIR64, // int32 to double
        LIR_u2f     = 49 | LIR64, // uint32 to double
        LIR_i2q     = 26 | LIR64, // sign-extend 32->64
        LIR_u2q     = 27 | LIR64, // zero-extend 32->64
        LIR_qaddp   = LIR_iaddp  | LIR64, // 64bit non-cse add
        LIR_qalloc  = LIR_ialloc | LIR64, // stack alloc (ptr64)
        LIR_qior    = LIR_or  | LIR64,  // int64 bitwise or
        LIR_qxor    = LIR_xor | LIR64, // 64bit xor

        LIR_qeq     = LIR_eq  | LIR64, // int64  ==
        LIR_qlt     = LIR_lt  | LIR64, // int64  <
        LIR_qgt     = LIR_gt  | LIR64, // int64  >
        LIR_qle     = LIR_le  | LIR64, // int64  <=
        LIR_qge     = LIR_ge  | LIR64, // int64  >=
        LIR_qult    = LIR_ult | LIR64, // uint64 <
        LIR_qugt    = LIR_ugt | LIR64, // uint64 >
        LIR_qule    = LIR_ule | LIR64, // uint64 <=
        LIR_quge    = LIR_uge | LIR64, // uint64 >=

        // alias
        LIR_ldp     = PTR_SIZE(LIR_ld,     LIR_ldq),
        LIR_ldcp    = PTR_SIZE(LIR_ldc,    LIR_ldqc),
        LIR_stp     = PTR_SIZE(LIR_st,     LIR_stq),
        LIR_piadd   = PTR_SIZE(LIR_add,    LIR_qiadd),
        LIR_piand   = PTR_SIZE(LIR_and,    LIR_qiand),
        LIR_pilsh   = PTR_SIZE(LIR_lsh,    LIR_qilsh),
        LIR_pirsh   = PTR_SIZE(LIR_rsh,    LIR_qirsh),
        LIR_pursh   = PTR_SIZE(LIR_ush,    LIR_qursh),
        LIR_pcmov   = PTR_SIZE(LIR_cmov,   LIR_qcmov),
        LIR_pior    = PTR_SIZE(LIR_or,     LIR_qior),
        LIR_pxor    = PTR_SIZE(LIR_xor,    LIR_qxor),
        LIR_addp    = PTR_SIZE(LIR_iaddp,  LIR_qaddp),
        LIR_peq     = PTR_SIZE(LIR_eq,     LIR_qeq),
        LIR_plt     = PTR_SIZE(LIR_lt,     LIR_qlt),
        LIR_pgt     = PTR_SIZE(LIR_gt,     LIR_qgt),
        LIR_ple     = PTR_SIZE(LIR_le,     LIR_qle),
        LIR_pge     = PTR_SIZE(LIR_ge,     LIR_qge),
        LIR_pult    = PTR_SIZE(LIR_ult,    LIR_qult),
        LIR_pugt    = PTR_SIZE(LIR_ugt,    LIR_qugt),
        LIR_pule    = PTR_SIZE(LIR_ule,    LIR_qule),
        LIR_puge    = PTR_SIZE(LIR_uge,    LIR_quge),
        LIR_alloc   = PTR_SIZE(LIR_ialloc, LIR_qalloc),
        LIR_pcall   = PTR_SIZE(LIR_icall,  LIR_qcall),
        LIR_param   = PTR_SIZE(LIR_iparam, LIR_qparam)
    };

    /*
     LOpcode encodings (table form, enum above must match!)

            +0          +32         +64         +96
     0      start       short
     1      nearskip    int         file        quad
     2      skip        ldc         line        ldqc
     3      neartramp   2
     4      tramp       neg                     fneg
     5                  add                     fadd
     6                  sub                     fsub
     7                  mul                     fmul
     8                  callh                   fdiv
     9      iaddp       and         qaddp       qjoin
     10     iparam      or          qparam      qior
     11     st          xor         stq         qxor
     12     ld          not         ldq
     13     ialloc      lsh         qalloc      qilsh
     14     sti         rsh         stqi        qirsh
     15     ret         ush         fret        qursh
     16     live        xt                      i2f
     17                 xf          qcall       u2f
     18     icall       qlo         fcall
     19     loop        qhi
     20     x           ldcb
     21     j           ov
     22     jt          cs
     23     jf          eq                      qeq
     24     label       lt          qiand       qlt
     25     ji          gt          qiadd       qgt
     26     feq         le          i2q         qle
     27     flt         ge          u2q         qge
     28     fgt         ult                     qult
     29     fle         ugt                     qugt
     30     fge         ule                     qule
     31     cmov        uge         qcmov       quge

    */

    /*
     * notes about particular instructions
     *
     * LIR_addp
     * is non-cse to avoid a bug with calculated interior pointers living
     * longer than the base pointer, causing an object to be freed too soon by
     * a non-interior-pointer-supporting collector.
     *
     * LIR_ov LIR_cs
     * (todo) -- how exactly are these assumed to be used?
     *
     * LIR_2
     * this is just a tuple of operands for the cmov instructions, since
     * they require three operands.  the tuple has no meaning otherwise.
     *
     * LIR_line & LIR_file
     * there is code in tamarin that uses these to build symbol tables to
     * integrate with the VTune profiler.  Much of this should be moved into
     * nanojit and factored to work with other profilers.
     */

    inline uint32_t argwords(uint32_t argc) {
        return (argc+3)>>2;
    }

    struct SideExit;

    enum AbiKind {
        ABI_FASTCALL,
        ABI_THISCALL,
        ABI_STDCALL,
        ABI_CDECL
    };

    enum ArgSize {
        ARGSIZE_NONE = 0,
        ARGSIZE_F = 1,      // double (64bit)
        ARGSIZE_I = 2,      // int32_t
        ARGSIZE_Q = 3,      // uint64_t
        ARGSIZE_U = 6,      // uint32_t
        ARGSIZE_MASK = 7,
        ARGSIZE_MASK_INT = 2,
        ARGSIZE_SHIFT = 3,

        // aliases
        ARGSIZE_P = PTR_SIZE(ARGSIZE_I, ARGSIZE_Q), // pointer
        ARGSIZE_LO = ARGSIZE_I, // int32_t
        ARGSIZE_B = ARGSIZE_I, // bool
        ARGSIZE_V = ARGSIZE_NONE  // void
    };

    enum IndirectCall {
        CALL_INDIRECT = 0
    };

    struct CallInfo
    {
        uintptr_t   _address;
        uint32_t    _argtypes:27;   // 9 3-bit fields indicating arg type, by ARGSIZE above (including ret type): a1 a2 a3 a4 a5 ret
        uint8_t     _cse:1;         // true if no side effects
        uint8_t     _fold:1;        // true if no side effects
        AbiKind     _abi:3;
        verbose_only ( const char* _name; )

        uint32_t FASTCALL _count_args(uint32_t mask) const;
        uint32_t get_sizes(ArgSize*) const;

        inline bool isIndirect() const {
            return _address < 256;
        }
        inline uint32_t FASTCALL count_args() const {
            return _count_args(ARGSIZE_MASK);
        }
        inline uint32_t FASTCALL count_iargs() const {
            return _count_args(ARGSIZE_MASK_INT);
        }
        // fargs = args - iargs
    };

    inline bool isGuard(LOpcode op) {
        return op==LIR_x || op==LIR_xf || op==LIR_xt || op==LIR_loop;
    }

    inline bool isCall(LOpcode op) {
        return (op & ~LIR64) == LIR_icall || op == LIR_qcall;
    }

    inline bool isStore(LOpcode op) {
        op = LOpcode(op & ~LIR64);
        return op == LIR_st || op == LIR_sti;
    }

    inline bool isConst(LOpcode op) {
        return (op & ~1) == LIR_short;
    }

    inline bool isLoad(LOpcode op) {
        return op == LIR_ldq || op == LIR_ld || op == LIR_ldc || op == LIR_ldqc;
    }

    // Sun Studio requires explicitly declaring signed int bit-field
    #if defined(__SUNPRO_C) || defined(__SUNPRO_CC)
    #define _sign_int signed int
    #else
    #define _sign_int int32_t
    #endif

    // Low-level Instruction 4B
    // had to lay it our as a union with duplicate code fields since msvc couldn't figure out how to compact it otherwise.
    class LIns
    {
        friend class LirBufWriter;
        // 3-operand form (backwards reach only)
        struct u_type
        {
            LOpcode         code:8;
            uint32_t        oprnd_3:8;  // only used for store, since this location gets clobbered during generation
            uint32_t        oprnd_1:8;  // 256 ins window and since they only point backwards this is sufficient.
            uint32_t        oprnd_2:8;
        };

        struct sti_type
        {
            LOpcode         code:8;
            _sign_int       disp:8;
            uint32_t        oprnd_1:8;  // 256 ins window and since they only point backwards this is sufficient.
            uint32_t        oprnd_2:8;
        };

        // imm8 form
        struct c_type
        {
            LOpcode         code:8;
            uint32_t        resv:8;  // cobberred during assembly
            uint32_t        imm8a:8;
            uint32_t        imm8b:8;
        };

        // imm24 form for short tramp & skip
        struct t_type
        {
            LOpcode         code:8;
            _sign_int       imm24:24;
        };

        // imm16 form
        struct i_type
        {
            LOpcode         code:8;
            uint32_t        resv:8;  // cobberred during assembly
            _sign_int       imm16:16;
        };

        // overlay used during code generation ( note that last byte is reserved for allocation )
        struct g_type
        {
            LOpcode         code:8;
            uint32_t        resv:8;   // cobberred during assembly
            uint32_t        unused:16;
        };

        #undef _sign_int

        /**
         * Various forms of the instruction.
         *
         *    In general the oprnd_x entries contain an uint value 0-255 that identifies a previous
         *    instruction, where 0 means the previous instruction and 255 means the instruction two
         *    hundred and fifty five prior to this one.
         *
         *    For pointing to instructions further than this range LIR_tramp is used.
         */
        union
        {
            u_type u;
            c_type c;
            i_type i;
            t_type t;
            g_type g;
            sti_type sti;
        };

        enum {
            callInfoWords = sizeof(LIns*)/sizeof(u_type)
        };

        uint32_t reference(LIns*) const;
        LIns* deref(int32_t off) const;

    public:
        LIns*       FASTCALL oprnd1() const;
        LIns*       FASTCALL oprnd2() const;
        LIns*       FASTCALL oprnd3() const;

        inline LOpcode  opcode() const  { return u.code; }
        inline uint8_t  imm8()   const  { return c.imm8a; }
        inline uint8_t  imm8b()  const  { return c.imm8b; }
        inline int16_t  imm16()  const  { return i.imm16; }
        inline int32_t  imm24()  const  { return t.imm24; }
        LIns*   ref()    const;
        int32_t imm32()  const;
        inline uint8_t  resv()   const  { return g.resv; }
        void*   payload() const;
        inline int32_t  size() const {
            NanoAssert(isop(LIR_alloc));
            return i.imm16<<2;
        }
        inline void setSize(int32_t bytes) {
            NanoAssert(isop(LIR_alloc) && (bytes&3)==0 && isU16(bytes>>2));
            i.imm16 = bytes>>2;
        }

        LIns* arg(uint32_t i);

        inline int32_t  immdisp()const
        {
            return (u.code&~LIR64) == LIR_sti ? sti.disp : oprnd3()->constval();
        }

        inline static bool sameop(LIns* a, LIns* b)
        {
            // hacky but more efficient than opcode() == opcode() due to bit masking of 7-bit field
            union {
                uint32_t x;
                u_type u;
            } tmp;
            tmp.x = *(uint32_t*)a ^ *(uint32_t*)b;
            return tmp.u.code == 0;
        }

        inline int32_t constval() const
        {
            NanoAssert(isconst());
            return isop(LIR_short) ? imm16() : imm32();
        }

        uint64_t constvalq() const;

    #ifdef NANOJIT_64BIT
        inline void* constvalp() const {
            return (void*)constvalq();
        }
        inline bool isPtr() const {
            return isQuad();
        }
    #else
        inline void* constvalp() const {
            return (void*)constval();
        }
        inline bool isPtr() const {
            return !isQuad();
        }
    #endif

        double constvalf() const;
        bool isCse() const;
        bool isop(LOpcode o) const { return u.code == o; }
        bool isQuad() const;
        bool isCond() const;
        bool isCmp() const;
        bool isCall() const { return nanojit::isCall(u.code); }
        bool isStore() const { return nanojit::isStore(u.code); }
        bool isLoad() const { return nanojit::isLoad(u.code); }
        bool isGuard() const { return nanojit::isGuard(u.code); }
        // True if the instruction is a 32-bit or smaller constant integer.
        bool isconst() const { return nanojit::isConst(u.code); }
        // True if the instruction is a 32-bit or smaller constant integer and
        // has the value val when treated as a 32-bit signed integer.
        bool isconstval(int32_t val) const;
        // True if the instruction is a constant quad value.
        bool isconstq() const;
        // True if the instruction is a constant pointer value.
        bool isconstp() const;
        bool isTramp() {
            return isop(LIR_neartramp) || isop(LIR_tramp);
        }
        bool isBranch() const {
            return isop(LIR_jt) || isop(LIR_jf) || isop(LIR_j);
        }
        // Set the imm16 member.  Should only be used on instructions that use
        // that.  If you're not sure, you shouldn't be calling it.
        void setimm16(int32_t i);
        void setimm24(int32_t x);
        // Set the resv member.  Should only be used on instructions that use
        // that.  If you're not sure, you shouldn't be calling it.
        void setresv(uint32_t resv);
        // Set the opcode
        void initOpcode(LOpcode);
        // operand-setting methods
        void setOprnd1(LIns*);
        void setOprnd2(LIns*);
        void setOprnd3(LIns*);
        void setDisp(int8_t d);
        void target(LIns* t);
        LIns **targetAddr();
        LIns* getTarget();

        SideExit *exit();

        inline uint32_t argc() const {
            NanoAssert(isCall());
            return c.imm8b;
        }
        size_t callInsWords() const;
        const CallInfo *callInfo() const;

        bool isPtr() {
            #ifdef NANOJIT_64BIT
                return isQuad();
            #else
                return !isQuad();
            #endif
        }
    };
    typedef LIns*       LInsp;

#ifdef ANDROID
    typedef struct { LIns* v; LIns i; } LirFarIns __attribute__ ((aligned (4)));
    typedef struct { int32_t v; LIns i; } LirImm32Ins __attribute__ ((aligned (4)));
    typedef struct { int32_t v[2]; LIns i; } LirImm64Ins __attribute__ ((aligned (4)));
    typedef struct { const CallInfo* ci; LIns i; } LirCallIns __attribute__ ((aligned (4)));
#else
#if defined __SUNPRO_C || defined __SUNPRO_CC
    #pragma pack(4)
#else
    #pragma pack(push, 4)
#endif

    typedef struct { LIns* v; LIns i; } LirFarIns;
    typedef struct { int32_t v; LIns i; } LirImm32Ins;
    typedef struct { int32_t v[2]; LIns i; } LirImm64Ins;
    typedef struct { const CallInfo* ci; LIns i; } LirCallIns;

#if defined __SUNPRO_C || defined __SUNPRO_CC
    #pragma pack(0)
#else
    #pragma pack(pop)
#endif
#endif // ANDROID

    static const uint32_t LIR_FAR_SLOTS   = sizeof(LirFarIns)/sizeof(LIns);
    static const uint32_t LIR_CALL_SLOTS = sizeof(LirCallIns)/sizeof(LIns);
    static const uint32_t LIR_IMM32_SLOTS = sizeof(LirImm32Ins)/sizeof(LIns);
    static const uint32_t LIR_IMM64_SLOTS = sizeof(LirImm64Ins)/sizeof(LIns);

    bool FASTCALL isCse(LOpcode v);
    bool FASTCALL isCmp(LOpcode v);
    bool FASTCALL isCond(LOpcode v);

    inline bool isRet(LOpcode c) {
        return (c & ~LIR64) == LIR_ret;
    }
    bool FASTCALL isFloat(LOpcode v);
    LIns* FASTCALL callArgN(LInsp i, uint32_t n);
    extern const uint8_t operandCount[];

    class Fragmento;    // @todo remove this ; needed for minbuild for some reason?!?  Should not be compiling this code at all
    class LirFilter;

    // make it a GCObject so we can explicitly delete it early
    class LirWriter : public GCFinalizedObject
    {
    public:
        LirWriter *out;

        LirWriter(LirWriter* out)
            : out(out) {}

        virtual LInsp ins0(LOpcode v) {
            return out->ins0(v);
        }
        virtual LInsp ins1(LOpcode v, LIns* a) {
            return out->ins1(v, a);
        }
        virtual LInsp ins2(LOpcode v, LIns* a, LIns* b) {
            return out->ins2(v, a, b);
        }
        virtual LInsp insGuard(LOpcode v, LIns *c, SideExit *x) {
            return out->insGuard(v, c, x);
        }
        virtual LInsp insBranch(LOpcode v, LInsp condition, LInsp to) {
            return out->insBranch(v, condition, to);
        }
        // arg: 0=first, 1=second, ...
        // kind: 0=arg 1=saved-reg
        virtual LInsp insParam(int32_t arg, int32_t kind) {
            return out->insParam(arg, kind);
        }
        virtual LInsp insImm(int32_t imm) {
            return out->insImm(imm);
        }
        virtual LInsp insImmq(uint64_t imm) {
            return out->insImmq(imm);
        }
        virtual LInsp insLoad(LOpcode op, LIns* base, LIns* d) {
            return out->insLoad(op, base, d);
        }
        virtual LInsp insStore(LIns* value, LIns* base, LIns* disp) {
            return out->insStore(value, base, disp);
        }
        virtual LInsp insStorei(LIns* value, LIns* base, int32_t d) {
            return isS8(d) ? out->insStorei(value, base, d)
                : out->insStore(value, base, insImm(d));
        }
        virtual LInsp insCall(const CallInfo *call, LInsp args[]) {
            return out->insCall(call, args);
        }
        virtual LInsp insAlloc(int32_t size) {
            return out->insAlloc(size);
        }

        // convenience
        LIns*       insLoadi(LIns *base, int disp);
        LIns*       insLoad(LOpcode op, LIns *base, int disp);
        LIns*       store(LIns* value, LIns* base, int32_t d);
        LIns*       ins_choose(LIns* cond, LIns* iftrue, LIns* iffalse);
        // Inserts an integer comparison to 0
        LIns*       ins_eq0(LIns* oprnd1);
        LIns*       ins2i(LOpcode op, LIns *oprnd1, int32_t);
        LIns*       qjoin(LInsp lo, LInsp hi);
        LIns*       insImmPtr(const void *ptr);
        LIns*       insImmf(double f);
    };

#ifdef NJ_VERBOSE
    extern const char* lirNames[];

    /**
     * map address ranges to meaningful names.
     */
    class LabelMap : public GCFinalizedObject
    {
        Allocator& allocator;
        LabelMap* parent;
        class Entry
        {
        public:
            Entry(int) : name(0), size(0), align(0) {}
            Entry(char *n, size_t s, size_t a) : name(n),size(s),align(a) {}
            char* name;
            size_t size:29, align:3;
        };
        avmplus::SortedMap<const void*, Entry*, avmplus::LIST_NonGCObjects> names;
        bool addrs, pad[3];
        char buf[1000], *end;
        void formatAddr(const void *p, char *buf);
    public:
        LabelMap(AvmCore* core, Allocator& allocator, LabelMap* parent);
        void add(const void *p, size_t size, size_t align, const char *name);
        const char *dup(const char *);
        const char *format(const void *p);
        void promoteAll(const void *newbase);
    };

    class LirNameMap : public GCFinalizedObject
    {
        Allocator& allocator;

        template <class Key>
        class CountMap: public avmplus::SortedMap<Key, int, avmplus::LIST_NonGCObjects> {
        public:
            CountMap(GC*gc) : avmplus::SortedMap<Key, int, avmplus::LIST_NonGCObjects>(gc) {}
            int add(Key k) {
                int c = 1;
                if (containsKey(k)) {
                    c = 1+get(k);
                }
                put(k,c);
                return c;
            }
        };
        CountMap<int> lircounts;
        CountMap<const CallInfo *> funccounts;

        class Entry
        {
        public:
            Entry(int) : name(0) {}
            Entry(char* n) : name(n) {}
            char* name;
        };
        avmplus::SortedMap<LInsp, Entry*, avmplus::LIST_NonGCObjects> names;
        LabelMap *labels;
        void formatImm(int32_t c, char *buf);
    public:

        LirNameMap(GC *gc, Allocator& allocator, LabelMap *r)
            : allocator(allocator),
            lircounts(gc),
            funccounts(gc),
            names(gc),
            labels(r)
        {}

        void addName(LInsp i, const char *s);
        void copyName(LInsp i, const char *s, int suffix);
        const char *formatRef(LIns *ref);
        const char *formatIns(LInsp i);
        void formatGuard(LInsp i, char *buf);
    };


    class VerboseWriter : public LirWriter
    {
        InsList code;
        DWB(LirNameMap*) names;
    public:
        VerboseWriter(GC *gc, LirWriter *out, LirNameMap* names)
            : LirWriter(out), code(gc), names(names)
        {}

        LInsp add(LInsp i) {
            if (i)
                code.add(i);
            return i;
        }

        LInsp add_flush(LInsp i) {
            if ((i = add(i)) != 0)
                flush();
            return i;
        }

        void flush()
        {
            int n = code.size();
            if (n) {
                for (int i=0; i < n; i++)
                    avmplus::AvmLog("    %s\n",names->formatIns(code[i]));
                code.clear();
                if (n > 1)
                    avmplus::AvmLog("\n");
            }
        }

        LIns* insGuard(LOpcode op, LInsp cond, SideExit *x) {
            return add_flush(out->insGuard(op,cond,x));
        }

        LIns* insBranch(LOpcode v, LInsp condition, LInsp to) {
            return add_flush(out->insBranch(v, condition, to));
        }

        LIns* ins0(LOpcode v) {
            if (v == LIR_label || v == LIR_start) {
                flush();
            }
            return add(out->ins0(v));
        }

        LIns* ins1(LOpcode v, LInsp a) {
            return isRet(v) ? add_flush(out->ins1(v, a)) : add(out->ins1(v, a));
        }
        LIns* ins2(LOpcode v, LInsp a, LInsp b) {
            return v == LIR_2 ? out->ins2(v,a,b) : add(out->ins2(v, a, b));
        }
        LIns* insCall(const CallInfo *call, LInsp args[]) {
            return add(out->insCall(call, args));
        }
        LIns* insParam(int32_t i, int32_t kind) {
            return add(out->insParam(i, kind));
        }
        LIns* insLoad(LOpcode v, LInsp base, LInsp disp) {
            return add(out->insLoad(v, base, disp));
        }
        LIns* insStore(LInsp v, LInsp b, LInsp d) {
            return add(out->insStore(v, b, d));
        }
        LIns* insStorei(LInsp v, LInsp b, int32_t d) {
            return add(out->insStorei(v, b, d));
        }
        LIns* insAlloc(int32_t size) {
            return add(out->insAlloc(size));
        }
    };

    class BBNode : public GCObject
    {
    public:

        enum BBKind
        {
            UNKNOWN = 0,
            FALL_THRU,
            ENDS_WITH_CALL,
            ENDS_WITH_RET
        };

        uint32_t num;   // unique id
        BBList  pred;   // list of predecssors
        BBList  succ;   // list of successors
        LInsp   start;
        LInsp   end;
        BBKind  kind;

        BBNode(GC* gc, uint32_t id) : pred(gc),succ(gc) { num=id; }
    };

    class BlockLocator : public LirWriter
    {
        LirWriter*  _out;
        GC*         _gc;
        BBNode*     _current;   // bb we are currently building
        BBNode*     _previous;  // bb we last built in linear fashion
        LInsp       _priorIns;  // last instruction seen
        BBList      _tbd;       // bb's where succ is unknown (last instruction is a forward jump)
        BBMap       _bbs;       // LInsp to bb
        uint32_t    _gid;       // unique id gen for bb's

    public:
        BlockLocator(GC* gc, LirWriter* out);

        BBNode* entry()         { return _bbs.get(0); }
        void    fin();
        void    print(char* name);

        // interface to LirWriter
        LInsp ins1(LOpcode v, LIns* a);
        LInsp ins2(LOpcode v, LIns* a, LIns* b);
        LInsp insLoad(LOpcode op, LIns* base, LIns* d);
        LInsp insStore(LIns* value, LIns* base, LIns* disp);
        LInsp insStorei(LIns* value, LIns* base, int32_t d);
        LInsp insCall(const CallInfo *call, LInsp args[]);
        LInsp insGuard(LOpcode v, LIns *c, SideExit *x);
        LInsp ins0(LOpcode v);
        LInsp insBranch(LOpcode v, LInsp condition, LInsp to);

    protected:
        BBNode* bbFor(LInsp n);
        void    ensureCurrent(LInsp n);
        void    blockEnd(LInsp at);
        LInsp   update(LInsp i);
        void    link(BBNode* from, BBNode* to);
    };

#endif

    class ExprFilter: public LirWriter
    {
    public:
        ExprFilter(LirWriter *out) : LirWriter(out) {}
        LIns* ins1(LOpcode v, LIns* a);
        LIns* ins2(LOpcode v, LIns* a, LIns* b);
        LIns* insGuard(LOpcode, LIns *cond, SideExit *);
        LIns* insBranch(LOpcode, LIns *cond, LIns *target);
        LIns* insLoad(LOpcode op, LInsp base, LInsp off);
    };

    // @todo, this could be replaced by a generic HashMap or HashSet, if we had one
    class LInsHashSet: public GCFinalizedObject
    {
        // must be a power of 2.
        // don't start too small, or we'll waste time growing and rehashing.
        // don't start too large, will waste memory.
        static const uint32_t kInitialCap = 64;

        LInsp *m_list; // explicit WB's are used, no DWB needed.
        uint32_t m_used, m_cap;
        GC* m_gc;

        static uint32_t FASTCALL hashcode(LInsp i);
        uint32_t FASTCALL find(LInsp name, uint32_t hash, const LInsp *list, uint32_t cap);
        static bool FASTCALL equals(LInsp a, LInsp b);
        void FASTCALL grow();

    public:

        LInsHashSet(GC* gc);
        LInsp find32(int32_t a, uint32_t &i);
        LInsp find64(uint64_t a, uint32_t &i);
        LInsp find1(LOpcode v, LInsp a, uint32_t &i);
        LInsp find2(LOpcode v, LInsp a, LInsp b, uint32_t &i);
        LInsp findcall(const CallInfo *call, uint32_t argc, LInsp args[], uint32_t &i);
        LInsp add(LInsp i, uint32_t k);
        void replace(LInsp i);
        void clear();

        static uint32_t FASTCALL hashimm(int32_t);
        static uint32_t FASTCALL hashimmq(uint64_t);
        static uint32_t FASTCALL hash1(LOpcode v, LInsp);
        static uint32_t FASTCALL hash2(LOpcode v, LInsp, LInsp);
        static uint32_t FASTCALL hashcall(const CallInfo *call, uint32_t argc, LInsp args[]);
    };

    class CseFilter: public LirWriter
    {
    public:
        LInsHashSet exprs;
        CseFilter(LirWriter *out, GC *gc);
        LIns* insImm(int32_t imm);
        LIns* insImmq(uint64_t q);
        LIns* ins1(LOpcode v, LInsp);
        LIns* ins2(LOpcode v, LInsp, LInsp);
        LIns* insLoad(LOpcode v, LInsp b, LInsp d);
        LIns* insCall(const CallInfo *call, LInsp args[]);
        LIns* insGuard(LOpcode op, LInsp cond, SideExit *x);
    };

    class LirBuffer : public GCFinalizedObject
    {
        public:
            LirBuffer(Allocator&);
            ~LirBuffer();
            void        clear();
            LInsp       next();

            verbose_only(DWB(LirNameMap*) names;)

            int32_t insCount();
            size_t byteCount();

            // stats
            struct
            {
                uint32_t lir;   // # instructions
            }
            _stats;

            AbiKind abi;
            LInsp state,param1,sp,rp;
            LInsp savedParams[NumSavedRegs];
            Allocator& allocator;

        protected:
            friend class LirBufWriter;

            /**
             * arbitrary segment size, determines allocation size.
             * Note: this is slightly under a multiple of 4K to avoid getting
             * a whole page of internal fragmentation.
             * as of 4/28/09 tamarin/MMgc requires 16-20 bytes of overhead per large alloc
             */
            static const uint32_t LIR_BUF_SEGMENT_SIZE = 32*1024-64;

            /** max # lir instructions that commit can handle, e.g. via skip() */
            static const uint32_t MAX_LIR_COMMIT = 1024;

            void        commit(uint32_t count);
            uint32_t    idx();
            uint32_t    maxIdx();
            uint32_t    thresholdIdx();
            void        transitionToNewSegment();

            uint32_t    _idx;
            LInsp       _currentSegment;
            size_t      _allocatedBytes;
    };

    class LirBufWriter : public LirWriter
    {
        DWB(LirBuffer*) _buf;       // underlying buffer housing the instructions
        LInsp spref, rpref;

        public:
            LirBufWriter(LirBuffer* buf)
                : LirWriter(0), _buf(buf)
            {}
            ~LirBufWriter() {}

            // LirWriter interface
            LInsp   insLoad(LOpcode op, LInsp base, LInsp off);
            LInsp   insStore(LInsp o1, LInsp o2, LInsp o3);
            LInsp   insStorei(LInsp o1, LInsp o2, int32_t imm);
            LInsp   ins0(LOpcode op);
            LInsp   ins1(LOpcode op, LInsp o1);
            LInsp   ins2(LOpcode op, LInsp o1, LInsp o2);
            LInsp   insParam(int32_t i, int32_t kind);
            LInsp   insImm(int32_t imm);
            LInsp   insImmq(uint64_t imm);
            LInsp   insCall(const CallInfo *call, LInsp args[]);
            LInsp   insGuard(LOpcode op, LInsp cond, SideExit *x);
            LInsp   insBranch(LOpcode v, LInsp condition, LInsp to);
            LInsp   insAlloc(int32_t size);

            // buffer mgmt
            LInsp   skip(size_t);

        protected:
            LInsp   insFar(LOpcode op, LInsp target);
            void    ensureRoom(size_t count);
            bool    can8bReach(LInsp from, LInsp to) { return isU8(from-to-1); }
            bool    can24bReach(LInsp from, LInsp to){ return isS24(from-to); }
            void    prepFor(LInsp& i1, LInsp& i2, LInsp& i3);
            void    makeReachable(LInsp& o, LInsp from);

        private:
            LInsp   insLinkTo(LOpcode op, LInsp to);     // does NOT call ensureRoom()
            LInsp   insLinkToFar(LOpcode op, LInsp to);  // does NOT call ensureRoom()
    };

    class LirFilter
    {
    public:
        LirFilter *in;
        LirFilter(LirFilter *in) : in(in) {}
        virtual ~LirFilter(){}

        virtual LInsp read() {
            return in->read();
        }
        virtual LInsp pos() {
            return in->pos();
        }
    };

    // concrete
    class LirReader : public LirFilter
    {
        LInsp _i; // current instruction that this decoder is operating on.

    public:
        LirReader(LirBuffer* buf) : LirFilter(0), _i(buf->next()-1) { }
        LirReader(LInsp i) : LirFilter(0), _i(i) { }

        // LirReader i/f
        LInsp read(); // advance to the prior instruction
        LInsp pos() {
            return _i;
        }
        void setpos(LIns *i) {
            _i = i;
        }
    };

    class Assembler;

    void compile(Fragmento*, Assembler*, Fragment*);
    verbose_only(void live(GC *gc, LirBuffer *lirbuf, bool showLiveRefs);)

    class StackFilter: public LirFilter
    {
        LirBuffer *lirbuf;
        LInsp sp;
        avmplus::BitSet stk;
        int top;
        int getTop(LInsp br);
    public:
        StackFilter(LirFilter *in, LirBuffer *lirbuf, LInsp sp);
        LInsp read();
    };

    class CseReader: public LirFilter
    {
        LInsHashSet *exprs;
    public:
        CseReader(LirFilter *in, LInsHashSet *exprs);
        LInsp read();
    };

    // eliminate redundant loads by watching for stores & mutator calls
    class LoadFilter: public LirWriter
    {
    public:
        LInsp sp, rp;
        LInsHashSet exprs;
        void clear(LInsp p);
    public:
        LoadFilter(LirWriter *out, GC *gc)
            : LirWriter(out), exprs(gc) { }

        LInsp ins0(LOpcode);
        LInsp insLoad(LOpcode, LInsp base, LInsp disp);
        LInsp insStore(LInsp v, LInsp b, LInsp d);
        LInsp insStorei(LInsp v, LInsp b, int32_t d);
        LInsp insCall(const CallInfo *call, LInsp args[]);
    };
}
#endif // __nanojit_LIR__
