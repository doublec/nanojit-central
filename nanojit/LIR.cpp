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
#include <stdio.h>

namespace nanojit
{
    using namespace avmplus;
	#ifdef FEATURE_NANOJIT

	const uint8_t operandCount[] = {
	/* 0 */		2, 2, /*trace*/0, /*nearskip*/0, /*skip*/0, /*neartramp*/0, /*tramp*/0, 2, 2, 2,
	/* 10 */	/*param*/0, 2, 2, 2, 2, 2, 2, 2, /*call*/0, /*loop*/0,
	/* 20 */	/*x*/0, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 30 */	2, 2, /*short*/0, /*int*/0, 2, 2, /*neg*/1, 2, 2, 2,
#if defined NANOJIT_64BIT
	/* 40 */	/*callh*/0, 2, 2, 2, /*not*/1, 2, 2, 2, /*xt*/1, /*xf*/1,
#else
	/* 40 */	/*callh*/1, 2, 2, 2, /*not*/1, 2, 2, 2, /*xt*/1, /*xf*/1,
#endif
	/* 50 */	/*qlo*/1, /*qhi*/1, 2, /*ov*/1, /*cs*/1, 2, 2, 2, 2, 2,
	/* 60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 80 */	2, 2, /*fcall*/0, 2, 2, 2, 2, 2, 2, 2,
	/* 90 */	2, 2, 2, 2, 2, 2, 2, /*quad*/0, 2, 2,
	/* 100 */	/*fneg*/1, 2, 2, 2, 2, 2, /*i2f*/1, /*u2f*/1, 2, 2,
	/* 110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 120 */	2, 2, 2, 2, 2, 2, 2, 2, 
	};

	// LIR verbose specific
	#ifdef NJ_VERBOSE

	const char* lirNames[] = {
	/* 0-9 */	"0","1","trace","nearskip","skip","neartramp","tramp","7","8","9",
	/* 10-19 */	"param","st","ld","13","sti","15","16","17","call","loop",
	/* 20-29 */ "x","21","22","23","24","25","feq","flt","fgt","fle",
	/* 30-39 */ "fge","cmov","short","int","ldc","","neg","add","sub","mul",
	/* 40-49 */ "callh","and","or","xor","not","lsh","rsh","ush","xt","xf",
	/* 50-59 */ "qlo","qhi","ldcb","ov","cs","eq","lt","gt","le","ge",
	/* 60-63 */ "ult","ugt","ule","uge",
	/* 64-69 */ "LIR64","65","66","67","68","69",
	/* 70-79 */ "70","71","72","73","74","stq","ldq","77","stqi","79",
	/* 80-89 */ "80","81","fcall","83","84","85","86","87","qiand","qiadd",
	/* 90-99 */ "90","91","92","93","qcmov","95","96","quad","98","99",
	/* 100-109 */ "fneg","fadd","fsub","fmul","fdiv","qjoin","i2f","u2f","108","qilsh",
	/* 110-119 */ "110","111","112","113","114","115","116","117","118","119",
	/* 120-127 */ "120","121","122","123","124","125","126","127"
	};

	#endif /* NANOJIT_VEBROSE */
	
	// implementation

#ifdef NJ_PROFILE
	// @todo fixup move to nanojit.h
	#undef counter_value
	#define counter_value(x)		x
#endif /* NJ_PROFILE */

	//static int32_t buffer_count = 0;
	
	// LCompressedBuffer
	LirBuffer::LirBuffer(Fragmento* frago, const CallInfo* functions)
		: _frago(frago), _functions(functions)
	{
		_start = 0;
		clear();
		_start = pageAlloc();
		if (_start)
		{
			verbose_only(_start->seq = 0;)
			_unused = &_start->lir[0];
		}
		//buffer_count++;
		//fprintf(stderr, "LirBuffer %x start %x\n", (int)this, (int)_start);
	}

	LirBuffer::~LirBuffer()
	{
		//buffer_count--;
		//fprintf(stderr, "~LirBuffer %x start %x\n", (int)this, (int)_start);
		clear();
#ifdef DEBUG		
        delete names;
#endif        
		_frago = 0;
	}
	
	void LirBuffer::clear()
	{
		// free all the memory and clear the stats
		debug_only( if (_start) validate();)
		while( _start )
		{
			Page *next = _start->next;
			_frago->pageFree( _start );
			_start = next;
			_stats.pages--;
		}
		NanoAssert(_stats.pages == 0);
		_unused = 0;
		_stats.lir = 0;
		_noMem = 0;
	}

	#ifdef _DEBUG
	void LirBuffer::validate() const
	{
		uint32_t count = 0;
		Page *last = 0;
		Page *page = _start;
		while(page)
		{
			last = page;
			page = page->next;
			count++;
		}
		NanoAssert(count == _stats.pages);
		NanoAssert(_noMem || _unused->page()->next == 0);
		NanoAssert(_noMem || samepage(last,_unused));
	}
	#endif 

#ifdef NJ_VERBOSE
	int LirBuffer::insCount() {
		return _stats.lir;
	}
	int LirBuffer::byteCount() {
		return (_stats.pages-1) * (sizeof(Page)-sizeof(PageHeader)) +
			(_unused - &_unused->page()->lir[0]) * sizeof(LIns);
	}
#endif

	Page* LirBuffer::pageAlloc()
	{
		Page* page = _frago->pageAlloc();
		if (page)
		{
			page->next = 0;	// end of list marker for new page
			_stats.pages++;
		}
		else
		{
			_noMem = 1;
		}
		return page;
	}
	
	LInsp LirBuffer::next()
	{
		debug_only( validate(); )
		return _unused;
	}

	bool LirBuffer::addPage()
	{
		LInsp last = _unused;
		// we need to pull in a new page and stamp the old one with a link to it
        Page *lastPage = last->page();
		Page *page = pageAlloc();
		if (page)
		{
			lastPage->next = page;  // forward link to next page 
			_unused = &page->lir[0];
            verbose_only(page->seq = lastPage->seq+1;)
			//fprintf(stderr, "Fragmento::ensureRoom stamping %x with %x; start %x unused %x\n", (int)pageBottom(last), (int)page, (int)_start, (int)_unused);
			debug_only( validate(); )
			return true;
		} 
		else {
			// mem failure, rewind pointer to top of page so that subsequent instruction works
			verbose_only(if (_frago->assm()->_verbose) _frago->assm()->outputf("page alloc failed");)
			_unused = &lastPage->lir[0];
		}
		return false;
	}
	
	bool LirBufWriter::ensureRoom(uint32_t count)
	{
		LInsp last = _buf->next();
		if (!samepage(last,last+2*count)
			&& _buf->addPage()) 
		{
			// link LIR stream back to prior instruction (careful insFar relies on _unused...)
			insFar(LIR_skip, last-1);
		}
		return !_buf->outOmem();
	}

	LInsp LirBuffer::commit(uint32_t count)
	{
		debug_only(validate();)
		NanoAssertMsg( samepage(_unused, _unused+count), "You need to call ensureRoom first!" );
		return _unused += count;
	}
	
	uint32_t LIns::reference(LIns *r) const
	{
		int delta = this-r-1;
		NanoAssert(isU8(delta));
		return delta;
	}

    LIns* LIns::deref(int32_t off) const
    {
		LInsp i = (LInsp) this-1 - off;
        while (i->isTramp())
            i = i->ref();
		return i;
    }

	LInsp LirBufWriter::ensureReferenceable(LInsp i, int32_t addedDistance)
	{
		NanoAssert(!i->isTramp());
		LInsp next = _buf->next();
		LInsp from = next + 2*addedDistance;
		if (canReference(from,i))
			return i;
        if (i == _buf->sp && spref && canReference(from, spref))
            return spref;
        if (i == _buf->rp && rpref && canReference(from, rpref))
            return rpref;

		// need a trampoline to get to i
		LInsp tramp = insFar(LIR_tramp, i);
		NanoAssert( tramp->ref() == i );

        if (i == _buf->sp)
            spref = tramp;
        else if (i == _buf->rp)
            rpref = tramp;
		return tramp;
	}
	
	LInsp LirBufWriter::insStore(LInsp val, LInsp base, LInsp off)
	{
		LOpcode op = val->isQuad() ? LIR_stq : LIR_st;
		NanoAssert(val && base && off);
		ensureRoom(4);
		LInsp r1 = ensureReferenceable(val,3);
		LInsp r2 = ensureReferenceable(base,2);
		LInsp r3 = ensureReferenceable(off,1);

		LInsp l = _buf->next();
		l->initOpcode(op);
		l->setOprnd1(r1);
		l->setOprnd2(r2);
		l->setOprnd3(r3);

		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
	}
	
	LInsp LirBufWriter::insStorei(LInsp val, LInsp base, int32_t d)
	{
		LOpcode op = val->isQuad() ? LIR_stqi : LIR_sti;
		NanoAssert(val && base && isS8(d));
		ensureRoom(3);
		LInsp r1 = ensureReferenceable(val,2);
		LInsp r2 = ensureReferenceable(base,1);

		LInsp l = _buf->next();
		l->initOpcode(op);
		l->setOprnd1(r1);
		l->setOprnd2(r2);
		l->setDisp(int8_t(d));

		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
	}

	LInsp LirBufWriter::ins0(LOpcode op)
	{
		ensureRoom(1);
		LInsp l = _buf->next();
		l->initOpcode(op);
		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
	}
	
	LInsp LirBufWriter::ins1(LOpcode op, LInsp o1)
	{
		ensureRoom(2);
		LInsp r1 = ensureReferenceable(o1,1);

		LInsp l = _buf->next();
		l->initOpcode(op);
		if (r1)
			l->setOprnd1(r1);

		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
	}
	
	LInsp LirBufWriter::ins2(LOpcode op, LInsp o1, LInsp o2)
	{
		ensureRoom(3);
		LInsp r1 = ensureReferenceable(o1,2);
		LInsp r2 = ensureReferenceable(o2,1);

		LInsp l = _buf->next();
		l->initOpcode(op);
		if (r1)
			l->setOprnd1(r1);
		if (r2)
			l->setOprnd2(r2);

		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
	}

	LInsp LirBufWriter::insLoad(LOpcode op, LInsp base, LInsp d)
	{
		return ins2(op,base,d);
	}

	LInsp LirBufWriter::insGuard(LOpcode op, LInsp c, SideExit *x)
	{
		LInsp data = skip(SideExitSize(x));
		*((SideExit*)data->payload()) = *x;
		return ins2(op, c, data);
	}

    LInsp LirBufWriter::insParam(int32_t arg)
    {
		ensureRoom(1);
		LInsp l = _buf->next();
		l->initOpcode(LIR_param);
		l->c.imm8a = Assembler::argRegs[arg];

		_buf->commit(1);
		_buf->_stats.lir++;
		return l;
    }
	
#define isS24(x) (((int32_t(x)<<8)>>8) == (x))

	LInsp LirBufWriter::insFar(LOpcode op, LInsp target)
	{
        NanoAssert(op == LIR_skip || op == LIR_tramp);
        LInsp l = _buf->next();
        int d = target-l;
        if (isS24(d)) {
    		ensureRoom(1);
            l->initOpcode(LOpcode(op-1)); // nearskip or neartramp
            l->t.imm24 = d;
            _buf->commit(1);
            return l;
        }
        else {
            ensureRoom(2);
            // write the pointer and instruction
            l = _buf->next()+1;
            *((LInsp*)(l-1)) = target;
            l->initOpcode(op);
            _buf->commit(2);
		    return l;
        }
	}
	
	LInsp LirBufWriter::insImm(int32_t imm)
	{
		if (isS16(imm)) {
			ensureRoom(1);
			LInsp l = _buf->next();
			l->initOpcode(LIR_short);
			l->setimm16(imm);
			_buf->commit(1);
			_buf->_stats.lir++;
			return l;
		} else {
			ensureRoom(2);
			int32_t* l = (int32_t*)_buf->next();
			*l = imm;
			_buf->commit(1);
			return ins0(LIR_int);
		}
	}
	
	LInsp LirBufWriter::insImmq(uint64_t imm)
	{
		ensureRoom(3);
		int32_t* l = (int32_t*)_buf->next();
		l[0] = int32_t(imm);
		l[1] = int32_t(imm>>32);
		_buf->commit(2);	
		return ins0(LIR_quad);
	}

	LInsp LirBufWriter::skip(size_t size)
	{
        const uint32_t n = (size+sizeof(LIns)-1)/sizeof(LIns);
		ensureRoom(n+2);
		LInsp last = _buf->next()-1;
		_buf->commit(n);
		return insFar(LIR_skip, last);
	}

	LInsp LirReader::read()	
	{
		LInsp cur = _i;
		if (!cur)
			return 0;
		LIns* i = cur;
		LOpcode iop = i->opcode();
		do
		{
			switch (iop)
			{					
				default:
					i--;
					break;

#if defined NANOJIT_64BIT
            	case LIR_callh:
#endif
				case LIR_call:
				case LIR_fcall:
					i -= argwords(i->argc())+1;
					break;

				case LIR_skip:
				case LIR_nearskip:
					NanoAssert(i->ref() != i);
					i = i->ref();
					break;

                case LIR_tramp:
				case LIR_int:
					NanoAssert(samepage(i, i-2));
					i -= 2;
					break;

				case LIR_quad:
					NanoAssert(samepage(i, i-3));
					i -= 3;
					break;

				case LIR_trace:
					_i = 0;  // start of trace
					return cur;
			}
			iop = i->opcode();
		}
		while (is_trace_skip_tramp(iop)||iop==LIR_2);
		_i = i;
		return cur;
	}

	bool FASTCALL isCmp(LOpcode c) {
		return c >= LIR_eq && c <= LIR_uge || c >= LIR_feq && c <= LIR_fge;
	}
    
	bool FASTCALL isCond(LOpcode c) {
		return (c == LIR_ov) || (c == LIR_cs) || isCmp(c);
	}
    
	bool LIns::isCmp() const {
		return nanojit::isCmp(u.code);
	}

    bool LIns::isCond() const {
        return nanojit::isCond(u.code);
    }
	
	bool LIns::isQuad() const {
		return ((u.code & LIR64) != 0 || u.code == LIR_callh);
	}
    
	bool LIns::isCall() const
	{
		return ((u.code&~LIR64) == LIR_call
				|| (u.code == LIR_callh));
	}

	bool LIns::isGuard() const
	{
		return u.code==LIR_x || u.code==LIR_xf || u.code==LIR_xt || u.code==LIR_loop;
	}

    bool LIns::isStore() const
    {
		int c = u.code & ~LIR64;
        return c == LIR_st || c == LIR_sti;
    }

    bool LIns::isLoad() const
    {
        return u.code == LIR_ldq || u.code == LIR_ld || u.code == LIR_ldc;
    }

	bool LIns::isconst() const
	{
		return (opcode()&~1) == LIR_short;
	}

	bool LIns::isconstval(int32_t val) const
	{
		return isconst() && constval()==val;
	}

	bool LIns::isconstq() const
	{	
		return isop(LIR_quad);
	}

	bool LIns::isconstp() const
	{
    #ifdef AVMPLUS_64BIT
	    return isconstq();
	#else
	    return isconst();
    #endif
	}

	bool FASTCALL isCse(LOpcode op) {
		op = LOpcode(op & ~LIR64);
		return op >= LIR_feq && op <= LIR_uge;
	}

    bool LIns::isCse(const CallInfo *functions) const
    { 
		return nanojit::isCse(u.code) || isCall() && functions[fid()]._cse;
    }

	void LIns::setimm16(int32_t x)
	{
		NanoAssert(isS16(x));
		i.imm16 = int16_t(x);
	}

	void LIns::setresv(uint32_t resv)
	{
		NanoAssert(isU8(resv));
		g.resv = resv;
	}

	void LIns::initOpcode(LOpcode op)
	{
		i.code = op;
		i.imm16 = 0;
        i.resv = 0;
	}

	void LIns::setOprnd1(LInsp r)
	{
		u.oprnd_1 = reference(r);
	}

	void LIns::setOprnd2(LInsp r)
	{
		u.oprnd_2 = reference(r);
	}

	void LIns::setOprnd3(LInsp r)
	{
		u.oprnd_3 = reference(r);
	}

    void LIns::setDisp(int8_t d)
    {
        sti.disp = d;
    }

	LInsp	LIns::oprnd1() const	
	{
        return deref(u.oprnd_1);
	}
	
	LInsp	LIns::oprnd2() const
	{ 
        return deref(u.oprnd_2);
	}

	LInsp	LIns::oprnd3() const
	{ 
        return deref(u.oprnd_3);
	}

    void *LIns::payload() const
    {
        NanoAssert(opcode()==LIR_skip || opcode()==LIR_nearskip);
        return (void*) (ref()+1);
    }

    LIns* LirWriter::ins2i(LOpcode v, LIns* oprnd1, int32_t imm)
    {
        return ins2(v, oprnd1, insImm(imm));
    }

    bool insIsS16(LInsp i)
    {
        if (i->isconst()) {
            int c = i->constval();
            return isS16(c);
        }
        if (i->isop(LIR_cmov) || i->isop(LIR_qcmov)) {
            LInsp vals = i->oprnd2();
            return insIsS16(vals->oprnd1()) && insIsS16(vals->oprnd2());
        }
        if (i->isCmp())
            return true;
        // many other possibilities too.
        return false;
    }

	LIns* ExprFilter::ins1(LOpcode v, LIns* i)
	{
		if (v == LIR_qlo) {
			if (i->isconstq())
				return insImm(int32_t(i->constvalq()));
			if (i->isop(LIR_qjoin))
				return i->oprnd1();
		}
		else if (v == LIR_qhi) {
			if (i->isconstq())
				return insImm(int32_t(i->constvalq()>>32));
			if (i->isop(LIR_qjoin))
				return i->oprnd2();
		}
		else if (v == i->opcode() && (v == LIR_not || v == LIR_neg || v == LIR_fneg)) {
			return i->oprnd1();
		}

		// todo
		// -(a-b) = b-a

		return out->ins1(v, i);
	}

	LIns* ExprFilter::ins2(LOpcode v, LIns* oprnd1, LIns* oprnd2)
	{
		NanoAssert(oprnd1 && oprnd2);
		if (v == LIR_cmov || v == LIR_qcmov) {
			if (oprnd2->oprnd1() == oprnd2->oprnd2()) {
				// c ? a : a => a
				return oprnd2->oprnd1();
			}
		}
		if (oprnd1 == oprnd2)
		{
			if (v == LIR_xor || v == LIR_sub ||
				v == LIR_ult || v == LIR_ugt || v == LIR_gt || v == LIR_lt)
				return insImm(0);
			if (v == LIR_or || v == LIR_and)
				return oprnd1;
			if (v == LIR_le || v == LIR_ule || v == LIR_ge || v == LIR_uge) {
				// x <= x == 1; x >= x == 1
				return insImm(1);
			}
		}
		if (oprnd1->isconst() && oprnd2->isconst())
		{
			int c1 = oprnd1->constval();
			int c2 = oprnd2->constval();
			if (v == LIR_qjoin) {
				uint64_t q = c1 | uint64_t(c2)<<32;
				return insImmq(q);
			}
			if (v == LIR_eq)
				return insImm(c1 == c2);
            if (v == LIR_ov)
                return insImm((c2 != 0) && ((c1 + c2) <= c1)); 
            if (v == LIR_cs)
                return insImm((c2 != 0) && ((uint32_t(c1) + uint32_t(c2)) <= uint32_t(c1)));
			if (v == LIR_lt)
				return insImm(c1 < c2);
			if (v == LIR_gt)
				return insImm(c1 > c2);
			if (v == LIR_le)
				return insImm(c1 <= c2);
			if (v == LIR_ge)
				return insImm(c1 >= c2);
			if (v == LIR_ult)
				return insImm(uint32_t(c1) < uint32_t(c2));
			if (v == LIR_ugt)
				return insImm(uint32_t(c1) > uint32_t(c2));
			if (v == LIR_ule)
				return insImm(uint32_t(c1) <= uint32_t(c2));
			if (v == LIR_uge)
				return insImm(uint32_t(c1) >= uint32_t(c2));
			if (v == LIR_rsh)
				return insImm(int32_t(c1) >> int32_t(c2));
			if (v == LIR_lsh)
				return insImm(int32_t(c1) << int32_t(c2));
			if (v == LIR_ush)
				return insImm(uint32_t(c1) >> int32_t(c2));
		}
		else if (oprnd1->isconstq() && oprnd2->isconstq())
		{
			double c1 = oprnd1->constvalf();
			double c2 = oprnd1->constvalf();
			if (v == LIR_feq)
				return insImm(c1 == c2);
			if (v == LIR_flt)
				return insImm(c1 < c2);
			if (v == LIR_fgt)
				return insImm(c1 > c2);
			if (v == LIR_fle)
				return insImm(c1 <= c2);
			if (v == LIR_fge)
				return insImm(c1 >= c2);
		}
		else if (oprnd1->isconst() && !oprnd2->isconst())
		{
			if (v == LIR_add || v == LIR_mul ||
				v == LIR_fadd || v == LIR_fmul ||
				v == LIR_xor || v == LIR_or || v == LIR_and ||
				v == LIR_eq) {
				// move const to rhs
				LIns* t = oprnd2;
				oprnd2 = oprnd1;
				oprnd1 = t;
			}
			else if (v >= LIR_lt && v <= LIR_uge) {
				// move const to rhs, swap the operator
				LIns *t = oprnd2;
				oprnd2 = oprnd1;
				oprnd1 = t;
				v = LOpcode(v^1);
			}
			else if (v == LIR_cmov || v == LIR_qcmov) {
				// const ? x : y => return x or y depending on const
				return oprnd1->constval() ? oprnd2->oprnd1() : oprnd2->oprnd2();
			}
		}

		if (oprnd2->isconst())
		{
			int c = oprnd2->constval();
			if (v == LIR_add && oprnd1->isop(LIR_add) && oprnd1->oprnd2()->isconst()) {
				// add(add(x,c1),c2) => add(x,c1+c2)
				c += oprnd1->oprnd2()->constval();
				oprnd2 = insImm(c);
				oprnd1 = oprnd1->oprnd1();
			}
			else if (v == LIR_sub && oprnd1->isop(LIR_add) && oprnd1->oprnd2()->isconst()) {
				// sub(add(x,c1),c2) => add(x,c1-c2)
				c = oprnd1->oprnd2()->constval() - c;
				oprnd2 = insImm(c);
				oprnd1 = oprnd1->oprnd1();
				v = LIR_add;
			}
			else if (v == LIR_rsh && c == 16 && oprnd1->isop(LIR_lsh) &&
					 oprnd1->oprnd2()->isconstval(16)) {
				if (insIsS16(oprnd1->oprnd1())) {
					// rsh(lhs(x,16),16) == x, if x is S16
					return oprnd1->oprnd1();
				}
			}
			else if (v == LIR_ult) {
				if (oprnd1->isop(LIR_cmov) || oprnd1->isop(LIR_qcmov)) {
					LInsp a = oprnd1->oprnd2()->oprnd1();
					LInsp b = oprnd1->oprnd2()->oprnd2();
					if (a->isconst() && b->isconst()) {
						bool a_lt = uint32_t(a->constval()) < uint32_t(oprnd2->constval());
						bool b_lt = uint32_t(b->constval()) < uint32_t(oprnd2->constval());
						if (a_lt == b_lt)
							return insImm(a_lt);
					}
				}
			}

			if (c == 0)
			{
				if (v == LIR_add || v == LIR_or || v == LIR_xor ||
					v == LIR_sub || v == LIR_lsh || v == LIR_rsh || v == LIR_ush)
					return oprnd1;
				else if (v == LIR_and || v == LIR_mul)
					return oprnd2;
				else if (v == LIR_eq && oprnd1->isop(LIR_or) && 
					oprnd1->oprnd2()->isconst() &&
					oprnd1->oprnd2()->constval() != 0) {
					// (x or c) != 0 if c != 0
					return insImm(0);
				}
			}
			else if (c == -1 || c == 1 && oprnd1->isCmp()) {
				if (v == LIR_or) {
					// x | -1 = -1, cmp | 1 = 1
					return oprnd2;
				}
				else if (v == LIR_and) {
					// x & -1 = x, cmp & 1 = cmp
					return oprnd1;
				}
			}
		}

		LInsp i;
		if (v == LIR_qjoin && oprnd1->isop(LIR_qlo) && oprnd2->isop(LIR_qhi) 
			&& (i = oprnd1->oprnd1()) == oprnd2->oprnd1()) {
			// qjoin(qlo(x),qhi(x)) == x
			return i;
		}

		return out->ins2(v, oprnd1, oprnd2);
	}

	LIns* ExprFilter::insGuard(LOpcode v, LInsp c, SideExit *x)
	{
		if (v == LIR_xt || v == LIR_xf) {
			if (c->isconst()) {
				if (v == LIR_xt && !c->constval() || v == LIR_xf && c->constval()) {
					return 0; // no guard needed
				}
				else {
					// need a way to EOT now, since this is trace end.
#ifdef JS_TRACER
				    AvmAssert(0);
#endif				    
					return out->insGuard(LIR_x, out->insImm(1), x);
				}
			}
			else {
				while (c->isop(LIR_eq) && c->oprnd1()->isCmp() && 
					c->oprnd2()->isconstval(0)) {
				    // xt(eq(cmp,0)) => xf(cmp)   or   xf(eq(cmp,0)) => xt(cmp)
				    v = LOpcode(v^1);
				    c = c->oprnd1();
				}
			}
		}
		return out->insGuard(v, c, x);
	}

    LIns* LirWriter::insLoadi(LIns *base, int disp) 
    { 
        return insLoad(LIR_ld,base,disp);
    }

	LIns* LirWriter::insLoad(LOpcode op, LIns *base, int disp)
	{
		return insLoad(op, base, insImm(disp));
	}

	LIns* LirWriter::ins_eq0(LIns* oprnd1)
	{
		return ins2i(LIR_eq, oprnd1, 0);
	}

	LIns* LirWriter::qjoin(LInsp lo, LInsp hi)
	{
		return ins2(LIR_qjoin, lo, hi);
	}

	LIns* LirWriter::insImmPtr(const void *ptr)
	{
		return sizeof(ptr) == 8 ? insImmq((uintptr_t)ptr) : insImm((intptr_t)ptr);
	}

	LIns* LirWriter::ins_choose(LIns* cond, LIns* iftrue, LIns* iffalse, bool hasConditionalMove)
	{
		// if not a conditional, make it implicitly an ==0 test (then flop results)
		if (!cond->isCmp())
		{
			cond = ins_eq0(cond);
			LInsp tmp = iftrue;
			iftrue = iffalse;
			iffalse = tmp;
		}

		if (hasConditionalMove)
		{
			return ins2(iftrue->isQuad() ? LIR_qcmov : LIR_cmov, cond, ins2(LIR_2, iftrue, iffalse));
		}

		// @todo -- it might be better to use a short conditional branch rather than
		// the bit-twiddling on systems that don't provide a conditional move instruction.
		LInsp ncond = ins1(LIR_neg, cond); // cond ? -1 : 0
		return ins2(LIR_or, 
					ins2(LIR_and, iftrue, ncond), 
					ins2(LIR_and, iffalse, ins1(LIR_not, ncond)));
	}

    LIns* LirBufWriter::insCall(uint32_t fid, LInsp args[])
	{
		static const LOpcode k_callmap[] = { LIR_call, LIR_fcall, LIR_call, LIR_callh };

		const CallInfo& ci = _functions[fid];
		uint32_t argt = ci._argtypes;
		LOpcode op = k_callmap[argt & 3];

        ArgSize sizes[10];
        uint32_t argc = ci.get_sizes(sizes);

#ifdef NJ_SOFTFLOAT
		if (op == LIR_fcall)
			op = LIR_callh;
		LInsp args2[5*2]; // arm could require 2 args per double
		int32_t j = 0;
		for (int32_t i = 0; i < 5; i++) {
			argt >>= 2;
			ArgSize a = ArgSize(argt&3);
			if (a == ARGSIZE_F) {
				LInsp q = args[i];
				args2[j++] = ins1(LIR_qhi, q);
				args2[j++] = ins1(LIR_qlo, q);
			} else if (a != ARGSIZE_NONE) {
				args2[j++] = args[i];
			}
		}
		args = args2;
        NanoAssert(j == argc);
#endif

		NanoAssert(argc < 8);
		uint32_t words = argwords(argc);
		ensureRoom(words+argc+1);  // ins size + possible tramps
		for (uint32_t i=0; i < argc; i++)
			args[i] = ensureReferenceable(args[i], argc-i);
		uint8_t* offs = (uint8_t*)_buf->next();
		LIns *l = _buf->next() + words;
		for (uint32_t i=0; i < argc; i++)
			offs[i] = (uint8_t) l->reference(args[i]);
#if defined NANOJIT_64BIT
		l->initOpcode(op);
#else
		l->initOpcode(op==LIR_callh ? LIR_call : op);
#endif
        l->c.imm8a = fid;
        l->c.imm8b = argc;
		_buf->commit(words+1);	
		_buf->_stats.lir++;
		return l;
	}

    using namespace avmplus;

	StackFilter::StackFilter(LirFilter *in, GC *gc, Fragment *frag, LInsp sp) 
		: LirFilter(in), gc(gc), frag(frag), sp(sp), top(0)
	{}

	LInsp StackFilter::read() 
	{
		for (;;) 
		{
			LInsp i = in->read();
			if (!i)
				return i;
			if (i->isStore())
			{
				LInsp base = i->oprnd2();
				if (base == sp) 
				{
					LInsp v = i->oprnd1();
					int d = i->immdisp() >> 2;
					if (d >= top) {
						continue;
					} else {
						d = top - d;
						if (v->isQuad()) {
							// storing 8 bytes
							if (stk.get(d) && stk.get(d-1)) {
								continue;
							} else {
								stk.set(gc, d);
								stk.set(gc, d-1);
							}
						}
						else {
							// storing 4 bytes
							if (stk.get(d))
								continue;
							else
								stk.set(gc, d);
						}
					}
				}
			}
			else if (i->isGuard())
			{
				stk.reset();
				top = getTop(i) >> 2;
			}
			return i;
		}
	}

	//
	// inlined/separated version of SuperFastHash
	// This content is copyrighted by Paul Hsieh, For reference see : http://www.azillionmonkeys.com/qed/hash.html
	//
	inline uint32_t _hash8(uint32_t hash, const uint8_t data)
	{
		hash += data;
		hash ^= hash << 10;
		hash += hash >> 1;
		return hash;
	}

	inline uint32_t _hash32(uint32_t hash, const uint32_t data)
	{
		const uint32_t dlo = data & 0xffff;
		const uint32_t dhi = data >> 16;
		hash += dlo;
		const uint32_t tmp = (dhi << 11) ^ hash;
		hash = (hash << 16) ^ tmp;
		hash += hash >> 11;
		return hash;
	}
	
	inline uint32_t _hashptr(uint32_t hash, const void* data)
	{
#ifdef NANOJIT_64BIT
		hash = _hash32(hash, uint32_t(uintptr_t(data) >> 32));
		hash = _hash32(hash, uint32_t(uintptr_t(data)));
		return hash;
#else
		return _hash32(hash, uint32_t(data));
#endif
	}

	inline uint32_t _hashfinish(uint32_t hash)
	{
		/* Force "avalanching" of final 127 bits */
		hash ^= hash << 3;
		hash += hash >> 5;
		hash ^= hash << 4;
		hash += hash >> 17;
		hash ^= hash << 25;
		hash += hash >> 6;
		return hash;
	}

	LInsHashSet::LInsHashSet(GC* gc) : 
			m_list(gc, kInitialCap), m_used(0), m_gc(gc)
	{
#ifdef MEMORY_INFO
		m_list.set_meminfo_name("LInsHashSet.list");
#endif
		m_list.set(kInitialCap-1, 0);
	}
	
	/*static*/ uint32_t FASTCALL LInsHashSet::hashcode(LInsp i)
	{
		const LOpcode op = i->opcode();
		switch (op)
		{
			case LIR_short:
				return hashimm(i->imm16());
			case LIR_int:
				return hashimm(i->imm32());
			case LIR_quad:
				return hashimmq(i->constvalq());
			case LIR_call:
			case LIR_fcall:
#if defined NANOJIT_64BIT
			case LIR_callh:
#endif
			{
				LInsp args[10];
				int32_t argc = i->argc();
				NanoAssert(argc < 10);
				for (int32_t j=0; j < argc; j++)
					args[j] = i->arg(j);
				return hashcall(i->fid(), argc, args);
			} 
			default:
				if (operandCount[op] == 2)
					return hash2(op, i->oprnd1(), i->oprnd2());
				else
					return hash1(op, i->oprnd1());
		}
	}

	/*static*/ bool FASTCALL LInsHashSet::equals(LInsp a, LInsp b) 
	{
		if (a==b)
			return true;
		AvmAssert(a->opcode() == b->opcode());
		const LOpcode op = a->opcode();
		switch (op)
		{
			case LIR_short:
			{
				return a->imm16() == b->imm16();
			} 
			case LIR_int:
			{
				return a->imm32() == b->imm32();
			} 
			case LIR_quad:
			{
				return a->constvalq() == b->constvalq();
			}
			case LIR_call:
			case LIR_fcall:
#if defined NANOJIT_64BIT
			case LIR_callh:
#endif
			{
				if (a->fid() != b->fid()) return false;
				uint32_t argc=a->argc();
                NanoAssert(argc == b->argc());
				for (uint32_t i=0; i < argc; i++)
					if (a->arg(i) != b->arg(i))
						return false;
				return true;
			} 
			default:
			{
				const uint32_t count = operandCount[op];
				if ((count >= 1 && a->oprnd1() != b->oprnd1()) ||
					(count >= 2 && a->oprnd2() != b->oprnd2()))
					return false;
				return true;
			}
		}
	}

	void FASTCALL LInsHashSet::grow()
	{
		const uint32_t newcap = m_list.size() << 1;
		InsList newlist(m_gc, newcap);
#ifdef MEMORY_INFO
		newlist.set_meminfo_name("LInsHashSet.list");
#endif
		newlist.set(newcap-1, 0);
		for (uint32_t i=0, n=m_list.size(); i < n; i++)
		{
			LInsp name = m_list.get(i);
			if (!name) continue;
			uint32_t j = find(name, hashcode(name), newlist, newcap);
			newlist.set(j, name);
		}
		m_list.become(newlist);
	}

	uint32_t FASTCALL LInsHashSet::find(LInsp name, uint32_t hash, const InsList& list, uint32_t cap)
	{
		const uint32_t bitmask = (cap - 1) & ~0x1;

		uint32_t n = 7 << 1;
		hash &= bitmask;  
		LInsp k;
		while ((k = list.get(hash)) != NULL &&
			(!LIns::sameop(k,name) || !equals(k, name)))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		return hash;
	}

	LInsp LInsHashSet::add(LInsp name, uint32_t k)
	{
		// this is relatively short-lived so let's try a more aggressive load factor
		// in the interest of improving performance
		if (((m_used+1)<<1) >= m_list.size()) // 0.50
		{
			grow();
			k = find(name, hashcode(name), m_list, m_list.size());
		}
		NanoAssert(!m_list.get(k));
		m_used++;
		m_list.set(k, name);
		return name;
	}

	void LInsHashSet::replace(LInsp i)
	{
		uint32_t k = find(i, hashcode(i), m_list, m_list.size());
		if (m_list.get(k)) {
			// already there, so replace it
			m_list.set(k, i);
		} else {
			add(i, k);
		}
	}

	uint32_t LInsHashSet::hashimm(int32_t a) {
		return _hashfinish(_hash32(0,a));
	}

	uint32_t LInsHashSet::hashimmq(uint64_t a) {
		uint32_t hash = _hash32(0, uint32_t(a >> 32));
		return _hashfinish(_hash32(hash, uint32_t(a)));
	}

	uint32_t LInsHashSet::hash1(LOpcode op, LInsp a) {
		uint32_t hash = _hash8(0,uint8_t(op));
		return _hashfinish(_hashptr(hash, a));
	}

	uint32_t LInsHashSet::hash2(LOpcode op, LInsp a, LInsp b) {
		uint32_t hash = _hash8(0,uint8_t(op));
		hash = _hashptr(hash, a);
		return _hashfinish(_hashptr(hash, b));
	}

	uint32_t LInsHashSet::hashcall(uint32_t fid, uint32_t argc, LInsp args[]) {
		uint32_t hash = _hash32(0,fid);
		for (int32_t j=argc-1; j >= 0; j--)
			hash = _hashptr(hash,args[j]);
		return _hashfinish(hash);
	}

	LInsp LInsHashSet::find32(int32_t a, uint32_t &i)
	{
		uint32_t cap = m_list.size();
		const InsList& list = m_list;
		const uint32_t bitmask = (cap - 1) & ~0x1;
		uint32_t hash = hashimm(a) & bitmask;
		uint32_t n = 7 << 1;
		LInsp k;
		while ((k = list.get(hash)) != NULL && 
			(!k->isconst() || k->constval() != a))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		i = hash;
		return k;
	}

	LInsp LInsHashSet::find64(uint64_t a, uint32_t &i)
	{
		uint32_t cap = m_list.size();
		const InsList& list = m_list;
		const uint32_t bitmask = (cap - 1) & ~0x1;
		uint32_t hash = hashimmq(a) & bitmask;  
		uint32_t n = 7 << 1;
		LInsp k;
		while ((k = list.get(hash)) != NULL && 
			(!k->isconstq() || k->constvalq() != a))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		i = hash;
		return k;
	}

	LInsp LInsHashSet::find1(LOpcode op, LInsp a, uint32_t &i)
	{
		uint32_t cap = m_list.size();
		const InsList& list = m_list;
		const uint32_t bitmask = (cap - 1) & ~0x1;
		uint32_t hash = hash1(op,a) & bitmask;  
		uint32_t n = 7 << 1;
		LInsp k;
		while ((k = list.get(hash)) != NULL && 
			(k->opcode() != op || k->oprnd1() != a))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		i = hash;
		return k;
	}

	LInsp LInsHashSet::find2(LOpcode op, LInsp a, LInsp b, uint32_t &i)
	{
		uint32_t cap = m_list.size();
		const InsList& list = m_list;
		const uint32_t bitmask = (cap - 1) & ~0x1;
		uint32_t hash = hash2(op,a,b) & bitmask;  
		uint32_t n = 7 << 1;
		LInsp k;
		while ((k = list.get(hash)) != NULL && 
			(k->opcode() != op || k->oprnd1() != a || k->oprnd2() != b))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		i = hash;
		return k;
	}

	bool argsmatch(LInsp i, uint32_t argc, LInsp args[])
	{
		for (uint32_t j=0; j < argc; j++)
			if (i->arg(j) != args[j])
				return false;
		return true;
	}

	LInsp LInsHashSet::findcall(uint32_t fid, uint32_t argc, LInsp args[], uint32_t &i)
	{
		uint32_t cap = m_list.size();
		const InsList& list = m_list;
		const uint32_t bitmask = (cap - 1) & ~0x1;
		uint32_t hash = hashcall(fid, argc, args) & bitmask;  
		uint32_t n = 7 << 1;
		LInsp k;
		while ((k = list.get(hash)) != NULL &&
			(!k->isCall() || k->fid() != fid || !argsmatch(k, argc, args)))
		{
			hash = (hash + (n += 2)) & bitmask;		// quadratic probe
		}
		i = hash;
		return k;
	}

    SideExit *LIns::exit()
    {
        NanoAssert(isGuard());
        return (SideExit*)oprnd2()->payload();
    }

#ifdef NJ_VERBOSE
    class RetiredEntry: public GCObject
    {
    public:
        List<LInsp, LIST_NonGCObjects> live;
        LInsp i;
        RetiredEntry(GC *gc): live(gc) {}
    };
	class LiveTable 
	{
	public:
		SortedMap<LInsp,LInsp,LIST_NonGCObjects> live;
        List<RetiredEntry*, LIST_GCObjects> retired;
		int maxlive;
		LiveTable(GC *gc) : live(gc), retired(gc), maxlive(0) {}
        ~LiveTable()
        {
            for (size_t i = 0; i < retired.size(); i++) {
                delete retired.get(i);
            }

        }
		void add(LInsp i, LInsp use) {
            if (!i->isconst() && !i->isconstq() && !live.containsKey(i)) {
                NanoAssert(i->opcode() < sizeof(lirNames) / sizeof(lirNames[0]));
                live.put(i,use);
            }
		}
        void retire(LInsp i, GC *gc) {
            RetiredEntry *e = new (gc) RetiredEntry(gc);
            e->i = i;
            for (int j=0, n=live.size(); j < n; j++) {
                LInsp l = live.keyAt(j);
                if (!l->isStore() && !l->isGuard())
                    e->live.add(l);
            }
            int size=0;
		    if ((size = e->live.size()) > maxlive)
			    maxlive = size;

            live.remove(i);
            retired.add(e);
		}
		bool contains(LInsp i) {
			return live.containsKey(i);
		}
	};

    void live(GC *gc, Assembler *assm, Fragment *frag)
	{
		// traverse backwards to find live exprs and a few other stats.

		LInsp sp = frag->lirbuf->sp;
		LInsp rp = frag->lirbuf->rp;
		LiveTable live(gc);
		uint32_t exits = 0;
		LirBuffer *lirbuf = frag->lirbuf;
        LirReader br(lirbuf);
		StackFilter sf(&br, gc, frag, sp);
		StackFilter r(&sf, gc, frag, rp);
        int total = 0;
        live.add(frag->lirbuf->state, r.pos());
		for (LInsp i = r.read(); i != 0; i = r.read())
		{
            total++;

            // first handle side-effect instructions
			if (i->isStore() || i->isGuard() ||
				i->isCall() && !assm->callInfoFor(i->fid())->_cse)
			{
				live.add(i,0);
                if (i->isGuard())
                    exits++;
			}

			// now propagate liveness
			if (live.contains(i))
			{
				live.retire(i,gc);
                NanoAssert(i->opcode() < sizeof(operandCount) / sizeof(operandCount[0]));
				if (i->isStore()) {
					live.add(i->oprnd2(),i); // base
					live.add(i->oprnd1(),i); // val
				}
                else if (i->isop(LIR_cmov) || i->isop(LIR_qcmov)) {
                    live.add(i->oprnd1(),i);
                    live.add(i->oprnd2()->oprnd1(),i);
                    live.add(i->oprnd2()->oprnd2(),i);
                }
				else if (operandCount[i->opcode()] == 1) {
				    live.add(i->oprnd1(),i);
				}
				else if (operandCount[i->opcode()] == 2) {
					live.add(i->oprnd1(),i);
					live.add(i->oprnd2(),i);
				}
				else if (i->isCall()) {
					for (int j=0, c=i->argc(); j < c; j++)
						live.add(i->arg(j),i);
				}
			}
		}
 
		assm->outputf("live instruction count %ld, total %ld, max pressure %d",
			live.retired.size(), total, live.maxlive);
        assm->outputf("side exits %ld", exits);

		// print live exprs, going forwards
		LirNameMap *names = frag->lirbuf->names;
		for (int j=live.retired.size()-1; j >= 0; j--) 
        {
            RetiredEntry *e = live.retired[j];
            char livebuf[1000], *s=livebuf;
            *s = 0;
            for (int k=0,n=e->live.size(); k < n; k++) {
				strcpy(s, names->formatRef(e->live[k]));
				s += strlen(s);
				*s++ = ' '; *s = 0;
				NanoAssert(s < livebuf+sizeof(livebuf));
            }
			printf("%-60s %s\n", livebuf, names->formatIns(e->i));
			if (e->i->isGuard())
				printf("\n");
		}
	}

    LabelMap::Entry::~Entry()
    {
        delete name;
    }

    LirNameMap::Entry::~Entry()
    {
        delete name;
    }

    LirNameMap::~LirNameMap()
    {
        Entry *e;

        while ((e = names.removeLast()) != NULL) {
            delete e;
        }
    }

	void LirNameMap::addName(LInsp i, Stringp name) {
		if (!names.containsKey(i)) { 
			Entry *e = new (labels->core->gc) Entry(name);
			names.put(i, e);
		}
	}
	void LirNameMap::addName(LInsp i, const char *name) {
		addName(i, labels->core->newString(name));
	}

	void LirNameMap::copyName(LInsp i, const char *s, int suffix) {
		char s2[200];
		sprintf(s2,"%s%d", s,suffix);
		addName(i, labels->core->newString(s2));
	}

	void LirNameMap::formatImm(int32_t c, char *buf) {
		if (c >= 10000 || c <= -10000)
			sprintf(buf,"#%s",labels->format((void*)c));
        else
            sprintf(buf,"%d", c);
	}

	const char* LirNameMap::formatRef(LIns *ref)
	{
		char buffer[200], *buf=buffer;
		buf[0]=0;
		GC *gc = labels->core->gc;
		if (names.containsKey(ref)) {
			StringNullTerminatedUTF8 cname(gc, names.get(ref)->name);
			strcat(buf, cname.c_str());
		}
		else if (ref->isconstq()) {
#if defined NANOJIT_64BIT
            sprintf(buf, "#0x%lx", (nj_printf_ld)ref->constvalq());
#else
			formatImm(uint32_t(ref->constvalq()>>32), buf);
			buf += strlen(buf);
			*buf++ = ':';
			formatImm(uint32_t(ref->constvalq()), buf);
#endif
		}
		else if (ref->isconst()) {
			formatImm(ref->constval(), buf);
		}
		else {
			if (ref->isCall()) {
				copyName(ref, _functions[ref->fid()]._name, funccounts.add(ref->fid()));
			} else {
                NanoAssert(ref->opcode() < sizeof(lirNames) / sizeof(lirNames[0]));
				copyName(ref, lirNames[ref->opcode()], lircounts.add(ref->opcode()));
			}
			StringNullTerminatedUTF8 cname(gc, names.get(ref)->name);
			strcat(buf, cname.c_str());
		}
		return labels->dup(buffer);
	}

	const char* LirNameMap::formatIns(LIns* i)
	{
		char sbuf[200];
		char *s = sbuf;
		if (!i->isStore() && !i->isGuard() && !i->isop(LIR_trace)) {
			sprintf(s, "%s = ", formatRef(i));
			s += strlen(s);
		}

		LOpcode op = i->opcode();
		switch(op)
		{
			case LIR_short:
			case LIR_int:
			{
                sprintf(s, "%s", formatRef(i));
				break;
			}

			case LIR_quad:
			{
				int32_t *p = (int32_t*) (i-2);
				sprintf(s, "#%X:%X", p[1], p[0]);
				break;
			}

			case LIR_loop:
			case LIR_trace:
				sprintf(s, "%s", lirNames[op]);
				break;

#if defined NANOJIT_64BIT
			case LIR_callh:
#endif
			case LIR_fcall:
			case LIR_call: {
				sprintf(s, "%s ( ", _functions[i->fid()]._name);
				for (int32_t j=i->argc()-1; j >= 0; j--) {
					s += strlen(s);
					sprintf(s, "%s ",formatRef(i->arg(j)));
				}
				s += strlen(s);
				sprintf(s, ")");
				break;
			}

			case LIR_param:
                sprintf(s, "%s %s", lirNames[op], gpn(i->imm8()));
				break;

			case LIR_neg:
			case LIR_fneg:
			case LIR_i2f:
			case LIR_u2f:
			case LIR_qlo:
			case LIR_qhi:
            case LIR_ov:
            case LIR_cs:
			case LIR_not: 
				sprintf(s, "%s %s", lirNames[op], formatRef(i->oprnd1()));
				break;

			case LIR_x:
			case LIR_xt:
			case LIR_xf:
				formatGuard(i, s);
				break;

			case LIR_add:
			case LIR_sub: 
		 	case LIR_mul: 
			case LIR_fadd:
			case LIR_fsub: 
		 	case LIR_fmul: 
			case LIR_fdiv: 
			case LIR_and: 
			case LIR_or: 
			case LIR_xor: 
			case LIR_lsh: 
			case LIR_rsh:
			case LIR_ush:
			case LIR_eq:
			case LIR_lt:
			case LIR_le:
			case LIR_gt:
			case LIR_ge:
			case LIR_ult:
			case LIR_ule:
			case LIR_ugt:
			case LIR_uge:
			case LIR_feq:
			case LIR_flt:
			case LIR_fle:
			case LIR_fgt:
			case LIR_fge:
			case LIR_qjoin:
            case LIR_qiadd:
            case LIR_qiand:
            case LIR_qilsh:
				sprintf(s, "%s %s, %s", lirNames[op],
					formatRef(i->oprnd1()), 
					formatRef(i->oprnd2()));
				break;

			case LIR_qcmov:
			case LIR_cmov:
                sprintf(s, "%s ? %s : %s", 
					formatRef(i->oprnd1()), 
					formatRef(i->oprnd2()->oprnd1()), 
					formatRef(i->oprnd2()->oprnd2()));
				break;

			case LIR_ld: 
			case LIR_ldc: 
			case LIR_ldq: 
			case LIR_ldcb: 
				sprintf(s, "%s %s[%s]", lirNames[op],
					formatRef(i->oprnd1()), 
					formatRef(i->oprnd2()));
				break;

			case LIR_st: 
            case LIR_sti:
			case LIR_stq: 
            case LIR_stqi:
				sprintf(s, "%s[%d] = %s", 
					formatRef(i->oprnd2()), 
					i->immdisp(), 
					formatRef(i->oprnd1()));
				break;

			default:
				sprintf(s, "?");
				break;
		}
		return labels->dup(sbuf);
	}


#endif
	CseFilter::CseFilter(LirWriter *out, GC *gc)
		: LirWriter(out), exprs(gc) {}

	LIns* CseFilter::insImm(int32_t imm)
	{
		uint32_t k;
		LInsp found = exprs.find32(imm, k);
		if (found)
			return found;
		return exprs.add(out->insImm(imm), k);
	}

	LIns* CseFilter::insImmq(uint64_t q)
	{
		uint32_t k;
		LInsp found = exprs.find64(q, k);
		if (found)
			return found;
		return exprs.add(out->insImmq(q), k);
	}

	LIns* CseFilter::ins1(LOpcode v, LInsp a)
	{
		if (isCse(v)) {
			NanoAssert(operandCount[v]==1);
			uint32_t k;
			LInsp found = exprs.find1(v, a, k);
			if (found)
				return found;
			return exprs.add(out->ins1(v,a), k);
		}
		return out->ins1(v,a);
	}

	LIns* CseFilter::ins2(LOpcode v, LInsp a, LInsp b)
	{
		if (isCse(v)) {
			NanoAssert(operandCount[v]==2);
			uint32_t k;
			LInsp found = exprs.find2(v, a, b, k);
			if (found)
				return found;
			return exprs.add(out->ins2(v,a,b), k);
		}
		return out->ins2(v,a,b);
	}

	LIns* CseFilter::insLoad(LOpcode v, LInsp base, LInsp disp)
	{
		if (isCse(v)) {
			NanoAssert(operandCount[v]==2);
			uint32_t k;
			LInsp found = exprs.find2(v, base, disp, k);
			if (found)
				return found;
			return exprs.add(out->insLoad(v,base,disp), k);
		}
		return out->insLoad(v,base,disp);
	}

	LInsp CseFilter::insGuard(LOpcode v, LInsp c, SideExit *x)
	{
		if (isCse(v)) {
			// conditional guard
			NanoAssert(operandCount[v]==1);
			uint32_t k;
			LInsp found = exprs.find1(v, c, k);
			if (found)
				return 0;
			return exprs.add(out->insGuard(v,c,x), k);
		}
		return out->insGuard(v, c, x);
	}

	LInsp CseFilter::insCall(uint32_t fid, LInsp args[])
	{
		const CallInfo *c = &_functions[fid];
		if (c->_cse) {
			uint32_t k;
            uint32_t argc = c->count_args();
			LInsp found = exprs.findcall(fid, argc, args, k);
			if (found)
				return found;
			return exprs.add(out->insCall(fid, args), k);
		}
		return out->insCall(fid, args);
	}

	CseReader::CseReader(LirFilter *in, LInsHashSet *exprs, const CallInfo *functions)
		: LirFilter(in), exprs(exprs), functions(functions)
	{}

	LInsp CseReader::read()
	{
		LInsp i = in->read();
		if (i) {
			if (i->isCse(functions))
				exprs->replace(i);
		}
		return i;
	}

    LIns* FASTCALL callArgN(LIns* i, uint32_t n)
	{
		return i->arg(i->argc()-n-1);
	}

    void compile(Assembler* assm, Fragment* triggerFrag)
    {
        Fragmento *frago = triggerFrag->lirbuf->_frago;
        AvmCore *core = frago->core();
        GC *gc = core->gc;

		verbose_only( StringList asmOutput(gc); )
		verbose_only( assm->_outputCache = &asmOutput; )

		verbose_only(if (assm->_verbose && core->config.verbose_live)
			live(gc, assm, triggerFrag);)

		bool treeCompile = core->config.tree_opt && (triggerFrag->kind == BranchTrace);
		RegAllocMap regMap(gc);
		NInsList loopJumps(gc);
#ifdef MEMORY_INFO
		loopJumps.set_meminfo_name("LIR loopjumps");
#endif
		assm->beginAssembly(triggerFrag, &regMap);

		//fprintf(stderr, "recompile trigger %X kind %d\n", (int)triggerFrag, triggerFrag->kind);
		Fragment* root = triggerFrag;
		if (treeCompile)
		{
			// recompile the entire tree
			root = triggerFrag->root;
			root->removeIntraLinks();
			root->unlink(assm);			// unlink all incoming jumps ; since the compile() can fail
			root->unlinkBranches(assm); // no one jumps into a branch (except from within the tree) so safe to clear the links table
			root->fragEntry = 0;
			root->releaseCode(frago);
			
			// do the tree branches
			Fragment* frag = root->treeBranches;
			while(frag)
			{
				// compile til no more frags
				if (frag->lastIns)
				{
					assm->assemble(frag, loopJumps);
					verbose_only(if (assm->_verbose) 
						assm->outputf("compiling branch %s ip %s",
							frago->labels->format(frag),
							frago->labels->format(frag->ip)); )
					
					NanoAssert(frag->kind == BranchTrace);
					RegAlloc* regs = new (gc) RegAlloc();
					assm->copyRegisters(regs);
					assm->releaseRegisters();
					SideExit* exit = frag->spawnedFrom->exit();
					regMap.put(exit, regs);
				}
				frag = frag->treeBranches;
			}
		}
		
		// now the the main trunk
		assm->assemble(root, loopJumps);
		verbose_only(if (assm->_verbose) 
			assm->outputf("compiling trunk %s",
				frago->labels->format(root));)
		assm->endAssembly(root, loopJumps);
			
		// reverse output so that assembly is displayed low-to-high
		verbose_only( assm->_outputCache = 0; )
		verbose_only(for(int i=asmOutput.size()-1; i>=0; --i) { assm->outputf("%s",asmOutput.get(i)); } );

		if (assm->error())
		{
			root->fragEntry = 0;
		}
		else
		{
			root->link(assm);
			if (treeCompile) root->linkBranches(assm);
		}

#if defined(NJ_VERBOSE)
        for (size_t i = 0; i < asmOutput.size(); i++) {
            gc->Free(asmOutput.get(i));
        }
#endif
    }

	#endif /* FEATURE_NANOJIT */

#if defined(NJ_VERBOSE)
    LabelMap::LabelMap(AvmCore *core, LabelMap* parent)
        : parent(parent), names(core->gc), addrs(core->config.verbose_addrs), end(buf), core(core)
	{}

    LabelMap::~LabelMap()
    {
        Entry *e;
        
        while ((e = names.removeLast()) != NULL) {
            delete e;
        } 
    }

    void LabelMap::add(const void *p, size_t size, size_t align, const char *name)
	{
		if (!this || names.containsKey(p))
			return;
		add(p, size, align, core->newString(name));
	}

    void LabelMap::add(const void *p, size_t size, size_t align, Stringp name)
    {
		if (!this || names.containsKey(p))
			return;
		Entry *e = new (core->gc) Entry(name, size<<align, align);
		names.put(p, e);
    }

    const char *LabelMap::format(const void *p)
    {
		char b[200];
		int i = names.findNear(p);
		if (i >= 0) {
			const void *start = names.keyAt(i);
			Entry *e = names.at(i);
			const void *end = (const char*)start + e->size;
			avmplus::StringNullTerminatedUTF8 cname(core->gc, e->name);
			const char *name = cname.c_str();
			if (p == start) {
				if (addrs)
					sprintf(b,"%p %s",p,name);
				else
					strcpy(b, name);
				return dup(b);
			}
			else if (p > start && p < end) {
				int d = (intptr_t(p)-intptr_t(start)) >> e->align;
				if (addrs)
					sprintf(b, "%p %s+%d", p, name, d);
				else
					sprintf(b,"%s+%d", name, d);
				return dup(b);
			}
			else {
				if (parent)
					return parent->format(p);

				sprintf(b, "%p", p);
				return dup(b);
			}
		}
		if (parent)
			return parent->format(p);

		sprintf(b, "%p", p);
		return dup(b);
    }

	const char *LabelMap::dup(const char *b)
	{
		int need = strlen(b)+1;
		char *s = end;
		end += need;
		if (end > buf+sizeof(buf)) {
			s = buf;
			end = s+need;
		}
		strcpy(s, b);
		return s;
	}

	// copy all labels to parent, adding newbase to label addresses
	void LabelMap::promoteAll(const void *newbase)
	{
		for (int i=0, n=names.size(); i < n; i++) {
			void *base = (char*)newbase + (intptr_t)names.keyAt(i);
			parent->names.put(base, names.at(i));
		}
	}
#endif // NJ_VERBOSE
}
	
