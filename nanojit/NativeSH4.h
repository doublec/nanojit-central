/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*-
 *
 * ***** BEGIN LICENSE BLOCK *****
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
 * STMicroelectronics.
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Cédric VINCENT <cedric.vincent@st.com> for STMicroelectronics
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

#ifndef __nanojit_NativeSH4__
#define __nanojit_NativeSH4__

namespace nanojit
{
    /***********************************************************************
     * Definitions for the register allocation.
     */

    // General purpose and ABI registers.
    enum Register {

        // Scratch registers (a.k.a caller-saved, a.k.a local).
        R0 = 0,
        R1,
        R2,
        R3, // Excluded from the regalloc because of its use as a hyper-scratch.
        R4,
        R5,
        R6,
        R7,

        // Saved registers (a.k.a callee-saved, a.k.a global).
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,

        // ABI registers, excluded from the register allocation.
        FP,
        SP,

        // Floatting-point registers.
        _D0,
        _F0 = _D0,
        _F1,
        _D1,
        _F2 = _D1,
        _F3,
        _D2,
        _F4 = _D2,
        _F5,
        _D3,
        _F6 = _D3,
        _F7,
        _D4,
        _F8 = _D4,
        _F9,
        _D5,
        _F10 = _D5,
        _F11,
        _D6,
        _F12 = _D6,
        _F13,
        _D7,
        _F14 = _D7, // Excluded from the regalloc because of its use as a hyper-scratch.
        _F15,

        // Helpers.
        FirstReg   = R0,
        LastReg    = _D7,
        deprecated_UnknownReg = LastReg + 2,
        UnspecifiedReg = LastReg + 2,
        Rtemp      = R3,
        Dtemp      = _D7
    };

    // There's 16 integer registers + 8 double registers on SH4.
    typedef uint32_t RegisterMask;

    static const int NumSavedRegs         = 6;
    static const RegisterMask SavedRegs   = ((1<<R8) | (1<<R9) | (1<<R10) | (1<<R11) | (1<<R12) | (1<<R13));
    static const RegisterMask ScratchRegs = ((1<<R0) | (1<<R1) | (1<<R2) | (1<<R4) | (1<<R5) | (1<<R6) | (1<<R7));

    static const RegisterMask GpRegs = ScratchRegs  | SavedRegs;
    static const RegisterMask FpRegs = ((1<<_D0) | (1<<_D1) | (1<<_D2) | (1<<_D3) | (1<<_D4) | (1<<_D5) | (1<<_D6));

#define IsFpReg(reg) ((rmask((Register)(reg)) & (FpRegs | (1<<_D7))) != 0)
#define IsGpReg(reg) ((rmask((Register)(reg)) & (GpRegs)) != 0)

    /***********************************************************************
     * Definitions for the code generation.
     */

    // Fixed instruction width of 16 bits.
    typedef uint16_t NIns;

    // Minimum size in bytes of an allocation for a code-buffer.
    const int32_t LARGEST_UNDERRUN_PROT = 32 * sizeof(NIns);

    // Maximum size in bytes of a patch for a branch, keep in sync' with nPatchBranch().
    const size_t LARGEST_BRANCH_PATCH = 3 * sizeof(NIns) + sizeof(uint32_t);

    // Maximum size in bytes of a stack entry.
#define NJ_MAX_STACK_ENTRY 4096

    // Minimum alignement for the stack pointer.
#define NJ_ALIGN_STACK 8

    // Support the extended load/store opcodes.
#define NJ_EXPANDED_LOADSTORE_SUPPORTED 1

    // Maximum size in bytes of a FP64 load, keep in sync' with asm_immd_nochk().
#define SH4_IMMD_NOCHK_SIZE (9 * sizeof(NIns) + 2 * sizeof(uint32_t))

    /***********************************************************************
     * Extensions specific to this platform.
     */

    verbose_only( extern const char* regNames[]; )

    // Extensions for the instruction assembler.
#define DECLARE_PLATFORM_ASSEMBLER()                                    \
    const static int NumArgRegs;                                        \
    const static int NumArgDregs;                                       \
    const static Register argRegs[4], retRegs[2];                       \
    const static Register argDregs[4], retDregs[1];                     \
    int max_stack_args;                                                 \
                                                                        \
    void nativePageReset();                                             \
    void nativePageSetup();                                             \
    void underrunProtect(int);                                          \
    bool simplifyOpcode(LOpcode &);                                     \
                                                                        \
    NIns *asm_immi(int, Register, bool force = false);                  \
    void asm_immd(uint64_t, Register);                                  \
    void asm_immd_nochk(uint64_t, Register);                            \
    void asm_arg_regi(LIns*, Register);                                 \
    void asm_arg_regd(LIns*, Register);                                 \
    void asm_arg_stacki(LIns*, int);                                    \
    void asm_arg_stackd(LIns*, int);                                    \
    void asm_base_offset(int, Register);                                \
    void asm_load32i(int, Register, Register);                          \
    void asm_load16i(int, Register, Register, bool);                    \
    void asm_load8i(int, Register, Register, bool);                     \
    void asm_load64d(int, Register, Register);                          \
    void asm_load32d(int, Register, Register);                          \
    void asm_store32i(Register, int, Register);                         \
    void asm_store16i(Register, int, Register);                         \
    void asm_store8i(Register, int, Register);                          \
    void asm_store64d(Register, int, Register);                         \
    void asm_store32d(Register, int, Register);                         \
    void asm_cmp(LOpcode, LIns*);                                       \
    NIns *asm_branch(bool, NIns *);                                     \
                                                                        \
    void MR(Register, Register);                                        \
    void JMP(NIns*, bool from_underrunProtect = false);                 \
                                                                        \
    void SH4_emit16(uint16_t value);                                    \
    void SH4_emit32(uint32_t value);                                    \
    void SH4_add_imm(int imm, Register Rx);                             \
    void SH4_add(Register Ry, Register Rx);                             \
    void SH4_addc(Register Ry, Register Rx);                            \
    void SH4_addv(Register Ry, Register Rx);                            \
    void SH4_and_imm_R0(int imm);                                       \
    void SH4_and(Register Ry, Register Rx);                             \
    void SH4_andb_imm_dispR0GBR(int imm);                               \
    void SH4_bra(int imm);                                              \
    void SH4_bsr(int imm);                                              \
    void SH4_bt(int imm);                                               \
    void SH4_bf(int imm);                                               \
    void SH4_bts(int imm);                                              \
    void SH4_bfs(int imm);                                              \
    void SH4_clrmac();                                                  \
    void SH4_clrs();                                                    \
    void SH4_clrt();                                                    \
    void SH4_cmpeq_imm_R0(int imm);                                     \
    void SH4_cmpeq(Register Ry, Register Rx);                           \
    void SH4_cmpge(Register Ry, Register Rx);                           \
    void SH4_cmpgt(Register Ry, Register Rx);                           \
    void SH4_cmphi(Register Ry, Register Rx);                           \
    void SH4_cmphs(Register Ry, Register Rx);                           \
    void SH4_cmppl(Register Rx);                                        \
    void SH4_cmppz(Register Rx);                                        \
    void SH4_cmpstr(Register Ry, Register Rx);                          \
    void SH4_div0s(Register Ry, Register Rx);                           \
    void SH4_div0u();                                                   \
    void SH4_div1(Register Ry, Register Rx);                            \
    void SH4_extsb(Register Ry, Register Rx);                           \
    void SH4_extsw(Register Ry, Register Rx);                           \
    void SH4_extub(Register Ry, Register Rx);                           \
    void SH4_extuw(Register Ry, Register Rx);                           \
    void SH4_icbi_indRx(Register Rx);                                   \
    void SH4_jmp_indRx(Register Rx);                                    \
    void SH4_jsr_indRx(Register Rx);                                    \
    void SH4_ldc_SR(Register Rx);                                       \
    void SH4_ldc_GBR(Register Rx);                                      \
    void SH4_ldc_SGR(Register Rx);                                      \
    void SH4_ldc_VBR(Register Rx);                                      \
    void SH4_ldc_SSR(Register Rx);                                      \
    void SH4_ldc_SPC(Register Rx);                                      \
    void SH4_ldc_DBR(Register Rx);                                      \
    void SH4_ldc_bank(Register Rx, int imm);                            \
    void SH4_ldcl_incRx_SR(Register Rx);                                \
    void SH4_ldcl_incRx_GBR(Register Rx);                               \
    void SH4_ldcl_incRx_VBR(Register Rx);                               \
    void SH4_ldcl_incRx_SGR(Register Rx);                               \
    void SH4_ldcl_incRx_SSR(Register Rx);                               \
    void SH4_ldcl_incRx_SPC(Register Rx);                               \
    void SH4_ldcl_incRx_DBR(Register Rx);                               \
    void SH4_ldcl_incRx_bank(Register Rx, int imm);                     \
    void SH4_lds_MACH(Register Rx);                                     \
    void SH4_lds_MACL(Register Rx);                                     \
    void SH4_lds_PR(Register Rx);                                       \
    void SH4_lds_FPUL(Register Ry);                                     \
    void SH4_lds_FPSCR(Register Ry);                                    \
    void SH4_ldsl_incRx_MACH(Register Rx);                              \
    void SH4_ldsl_incRx_MACL(Register Rx);                              \
    void SH4_ldsl_incRx_PR(Register Rx);                                \
    void SH4_ldsl_incRy_FPUL(Register Ry);                              \
    void SH4_ldsl_incRy_FPSCR(Register Ry);                             \
    void SH4_ldtlb();                                                   \
    void SH4_macw_incRy_incRx(Register Ry, Register Rx);                \
    void SH4_mov_imm(int imm, Register Rx);                             \
    void SH4_mov(Register Ry, Register Rx);                             \
    void SH4_movb_dispR0Rx(Register Ry, Register Rx);                   \
    void SH4_movb_decRx(Register Ry, Register Rx);                      \
    void SH4_movb_indRx(Register Ry, Register Rx);                      \
    void SH4_movb_dispRy_R0(int imm, Register Ry);                      \
    void SH4_movb_dispGBR_R0(int imm);                                  \
    void SH4_movb_dispR0Ry(Register Ry, Register Rx);                   \
    void SH4_movb_incRy(Register Ry, Register Rx);                      \
    void SH4_movb_indRy(Register Ry, Register Rx);                      \
    void SH4_movb_R0_dispRx(int imm, Register Ry);                      \
    void SH4_movb_R0_dispGBR(int imm);                                  \
    void SH4_movl_dispRx(Register Ry, int imm, Register Rx);            \
    void SH4_movl_dispR0Rx(Register Ry, Register Rx);                   \
    void SH4_movl_decRx(Register Ry, Register Rx);                      \
    void SH4_movl_indRx(Register Ry, Register Rx);                      \
    void SH4_movl_dispRy(int imm, Register Ry, Register Rx);            \
    void SH4_movl_dispGBR_R0(int imm);                                  \
    void SH4_movl_dispPC(int imm, Register Rx);                         \
    void SH4_movl_dispR0Ry(Register Ry, Register Rx);                   \
    void SH4_movl_incRy(Register Ry, Register Rx);                      \
    void SH4_movl_indRy(Register Ry, Register Rx);                      \
    void SH4_movl_R0_dispGBR(int imm);                                  \
    void SH4_movw_dispR0Rx(Register Ry, Register Rx);                   \
    void SH4_movw_decRx(Register Ry, Register Rx);                      \
    void SH4_movw_indRx(Register Ry, Register Rx);                      \
    void SH4_movw_dispRy_R0(int imm, Register Ry);                      \
    void SH4_movw_dispGBR_R0(int imm);                                  \
    void SH4_movw_dispPC(int imm, Register Rx);                         \
    void SH4_movw_dispR0Ry(Register Ry, Register Rx);                   \
    void SH4_movw_incRy(Register Ry, Register Rx);                      \
    void SH4_movw_indRy(Register Ry, Register Rx);                      \
    void SH4_movw_R0_dispRx(int imm, Register Ry);                      \
    void SH4_movw_R0_dispGBR(int imm);                                  \
    void SH4_mova_dispPC_R0(int imm);                                   \
    void SH4_movcal_R0_indRx(Register Rx);                              \
    void SH4_movcol_R0_indRx(Register Rx);                              \
    void SH4_movlil_indRy_R0(Register Ry);                              \
    void SH4_movt(Register Rx);                                         \
    void SH4_movual_indRy_R0(Register Ry);                              \
    void SH4_movual_incRy_R0(Register Ry);                              \
    void SH4_mulsw(Register Ry, Register Rx);                           \
    void SH4_muls(Register Ry, Register Rx);                            \
    void SH4_mull(Register Ry, Register Rx);                            \
    void SH4_muluw(Register Ry, Register Rx);                           \
    void SH4_mulu(Register Ry, Register Rx);                            \
    void SH4_neg(Register Ry, Register Rx);                             \
    void SH4_negc(Register Ry, Register Rx);                            \
    void SH4_nop();                                                     \
    void SH4_not(Register Ry, Register Rx);                             \
    void SH4_ocbi_indRx(Register Rx);                                   \
    void SH4_ocbp_indRx(Register Rx);                                   \
    void SH4_ocbwb_indRx(Register Rx);                                  \
    void SH4_or_imm_R0(int imm);                                        \
    void SH4_or(Register Ry, Register Rx);                              \
    void SH4_orb_imm_dispR0GBR(int imm);                                \
    void SH4_pref_indRx(Register Rx);                                   \
    void SH4_prefi_indRx(Register Rx);                                  \
    void SH4_rotcl(Register Rx);                                        \
    void SH4_rotcr(Register Rx);                                        \
    void SH4_rotl(Register Rx);                                         \
    void SH4_rotr(Register Rx);                                         \
    void SH4_rte();                                                     \
    void SH4_rts();                                                     \
    void SH4_sets();                                                    \
    void SH4_sett();                                                    \
    void SH4_shad(Register Ry, Register Rx);                            \
    void SH4_shld(Register Ry, Register Rx);                            \
    void SH4_shal(Register Rx);                                         \
    void SH4_shar(Register Rx);                                         \
    void SH4_shll(Register Rx);                                         \
    void SH4_shll16(Register Rx);                                       \
    void SH4_shll2(Register Rx);                                        \
    void SH4_shll8(Register Rx);                                        \
    void SH4_shlr(Register Rx);                                         \
    void SH4_shlr16(Register Rx);                                       \
    void SH4_shlr2(Register Rx);                                        \
    void SH4_shlr8(Register Rx);                                        \
    void SH4_sleep();                                                   \
    void SH4_stc_SR(Register Rx);                                       \
    void SH4_stc_GBR(Register Rx);                                      \
    void SH4_stc_VBR(Register Rx);                                      \
    void SH4_stc_SSR(Register Rx);                                      \
    void SH4_stc_SPC(Register Rx);                                      \
    void SH4_stc_SGR(Register Rx);                                      \
    void SH4_stc_DBR(Register Rx);                                      \
    void SH4_stc_bank(int imm, Register Rx);                            \
    void SH4_stcl_SR_decRx(Register Rx);                                \
    void SH4_stcl_VBR_decRx(Register Rx);                               \
    void SH4_stcl_SSR_decRx(Register Rx);                               \
    void SH4_stcl_SPC_decRx(Register Rx);                               \
    void SH4_stcl_GBR_decRx(Register Rx);                               \
    void SH4_stcl_SGR_decRx(Register Rx);                               \
    void SH4_stcl_DBR_decRx(Register Rx);                               \
    void SH4_stcl_bank_decRx(int imm, Register Rx);                     \
    void SH4_sts_MACH(Register Rx);                                     \
    void SH4_sts_MACL(Register Rx);                                     \
    void SH4_sts_PR(Register Rx);                                       \
    void SH4_sts_FPUL(Register Rx);                                     \
    void SH4_sts_FPSCR(Register Rx);                                    \
    void SH4_stsl_MACH_decRx(Register Rx);                              \
    void SH4_stsl_MACL_decRx(Register Rx);                              \
    void SH4_stsl_PR_decRx(Register Rx);                                \
    void SH4_stsl_FPUL_decRx(Register Rx);                              \
    void SH4_stsl_FPSCR_decRx(Register Rx);                             \
    void SH4_sub(Register Ry, Register Rx);                             \
    void SH4_subc(Register Ry, Register Rx);                            \
    void SH4_subv(Register Ry, Register Rx);                            \
    void SH4_swapb(Register Ry, Register Rx);                           \
    void SH4_swapw(Register Ry, Register Rx);                           \
    void SH4_synco();                                                   \
    void SH4_tasb_indRx(Register Rx);                                   \
    void SH4_trapa_imm(int imm);                                        \
    void SH4_tst_imm_R0(int imm);                                       \
    void SH4_tst(Register Ry, Register Rx);                             \
    void SH4_tstb_imm_dispR0GBR(int imm);                               \
    void SH4_xor_imm_R0(int imm);                                       \
    void SH4_xor(Register Ry, Register Rx);                             \
    void SH4_xorb_imm_dispR0GBR(int imm);                               \
    void SH4_xtrct(Register Ry, Register Rx);                           \
    void SH4_dt(Register Rx);                                           \
    void SH4_dmulsl(Register Ry, Register Rx);                          \
    void SH4_dmulul(Register Ry, Register Rx);                          \
    void SH4_macl_incRy_incRx(Register Ry, Register Rx);                \
    void SH4_braf(Register Rx);                                         \
    void SH4_bsrf(Register Rx);                                         \
    void SH4_fabs(Register Rx);                                         \
    void SH4_fabs_double(Register Rx);                                  \
    void SH4_fadd(Register Ry, Register Rx);                            \
    void SH4_fadd_double(Register Ry, Register Rx);                     \
    void SH4_fcmpeq(Register Ry, Register Rx);                          \
    void SH4_fcmpeq_double(Register Ry, Register Rx);                   \
    void SH4_fcmpgt(Register Ry, Register Rx);                          \
    void SH4_fcmpgt_double(Register Ry, Register Rx);                   \
    void SH4_fcnvds_double_FPUL(Register Rx);                           \
    void SH4_fcnvsd_FPUL_double(Register Rx);                           \
    void SH4_fdiv(Register Ry, Register Rx);                            \
    void SH4_fdiv_double(Register Ry, Register Rx);                     \
    void SH4_fipr(Register Ry, Register Rx);                            \
    void SH4_fldi0(Register Rx);                                        \
    void SH4_fldi1(Register Rx);                                        \
    void SH4_flds_FPUL(Register Rx);                                    \
    void SH4_float_FPUL(Register Rx);                                   \
    void SH4_float_FPUL_double(Register Rx);                            \
    void SH4_fmac(Register Ry, Register Rx);                            \
    void SH4_fmov(Register Ry, Register Rx);                            \
    void SH4_fmov_Xdouble_Xdouble(Register Ry, Register Rx);            \
    void SH4_fmov_indRy(Register Ry, Register Rx);                      \
    void SH4_fmov_indRy_Xdouble(Register Ry, Register Rx);              \
    void SH4_fmov_indRx(Register Ry, Register Rx);                      \
    void SH4_fmov_Xdouble_indRx(Register Ry, Register Rx);              \
    void SH4_fmov_incRy(Register Ry, Register Rx);                      \
    void SH4_fmov_incRy_Xdouble(Register Ry, Register Rx);              \
    void SH4_fmov_decRx(Register Ry, Register Rx);                      \
    void SH4_fmov_Xdouble_decRx(Register Ry, Register Rx);              \
    void SH4_fmov_dispR0Ry(Register Ry, Register Rx);                   \
    void SH4_fmov_dispR0Ry_Xdouble(Register Ry, Register Rx);           \
    void SH4_fmov_dispR0Rx(Register Ry, Register Rx);                   \
    void SH4_fmov_Xdouble_dispR0Rx(Register Ry, Register Rx);           \
    void SH4_fmovd_indRy_Xdouble(Register Ry, Register Rx);             \
    void SH4_fmovd_Xdouble_indRx(Register Ry, Register Rx);             \
    void SH4_fmovd_incRy_Xdouble(Register Ry, Register Rx);             \
    void SH4_fmovd_Xdouble_decRx(Register Ry, Register Rx);             \
    void SH4_fmovd_dispR0Ry_Xdouble(Register Ry, Register Rx);          \
    void SH4_fmovd_Xdouble_dispR0Rx(Register Ry, Register Rx);          \
    void SH4_fmovs_indRy(Register Ry, Register Rx);                     \
    void SH4_fmovs_indRx(Register Ry, Register Rx);                     \
    void SH4_fmovs_incRy(Register Ry, Register Rx);                     \
    void SH4_fmovs_decRx(Register Ry, Register Rx);                     \
    void SH4_fmovs_dispR0Ry(Register Ry, Register Rx);                  \
    void SH4_fmovs_dispR0Rx(Register Ry, Register Rx);                  \
    void SH4_fmul(Register Ry, Register Rx);                            \
    void SH4_fmul_double(Register Ry, Register Rx);                     \
    void SH4_fneg(Register Rx);                                         \
    void SH4_fneg_double(Register Rx);                                  \
    void SH4_fpchg();                                                   \
    void SH4_frchg();                                                   \
    void SH4_fsca_FPUL_double(Register Rx);                             \
    void SH4_fschg();                                                   \
    void SH4_fsqrt(Register Rx);                                        \
    void SH4_fsqrt_double(Register Rx);                                 \
    void SH4_fsrra(Register Rx);                                        \
    void SH4_fsts_FPUL(Register Rx);                                    \
    void SH4_fsub(Register Ry, Register Rx);                            \
    void SH4_fsub_double(Register Ry, Register Rx);                     \
    void SH4_ftrc_FPUL(Register Rx);                                    \
    void SH4_ftrc_double_FPUL(Register Rx);                             \
    void SH4_ftrv(Register Rx);

    // Extensions for the register allocation, not [yet] used for the SH4.
#define DECLARE_PLATFORM_REGALLOC()

    // Extensions for the statistic computation, not [yet] used for the SH4.
#define DECLARE_PLATFORM_STATS()

    // Supports float->int conversion.
#define NJ_F2I_SUPPORTED 1

}

#endif /* __nanojit_NativeSH4__ */
