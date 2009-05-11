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

#include "nanojit.h"
#undef MMGC_MEMORY_INFO

namespace nanojit
{	
	#ifdef FEATURE_NANOJIT

	using namespace avmplus;

	static uint32_t calcSaneCacheSize(uint32_t in)
	{
		if (in < uint32_t(NJ_LOG2_PAGE_SIZE)) return NJ_LOG2_PAGE_SIZE;	// at least 1 page
		if (in > uint32_t(Fragmento::MAX_CACHE_SIZE_LOG2)) return Fragmento::MAX_CACHE_SIZE_LOG2;
		return in;
	}

	/**
	 * This is the main control center for creating and managing fragments.
	 */
	Fragmento::Fragmento(AvmCore* core, uint32_t cacheSizeLog2, CodeAlloc* codeAlloc) 
		:  _core(core),
		   _codeAlloc(codeAlloc),
		   _frags(core->GetGC()), 
		    _max_pages(1 << (calcSaneCacheSize(cacheSizeLog2) - NJ_LOG2_PAGE_SIZE)),
			_pagesGrowth(16)
	{
		NanoAssert(_max_pages > _pagesGrowth); // shrink growth if needed 
		verbose_only( enterCounts = NJ_NEW(core->gc, BlockHist)(core->gc); )
		verbose_only( mergeCounts = NJ_NEW(core->gc, BlockHist)(core->gc); )
	}

	Fragmento::~Fragmento()
	{
		clearFrags();
        _frags.clear();		
#if defined(NJ_VERBOSE)
        //NJ_DELETE(enterCounts);
        //NJ_DELETE(mergeCounts);
#endif
	}
	
	void Fragmento::clearFrags()
	{
        while (!_frags.isEmpty()) {
            Fragment *f = _frags.removeLast();
            Fragment *peer = f->peer;
            while (peer) {
                Fragment *next = peer->peer;
                peer->releaseTreeMem(_codeAlloc);
                NJ_DELETE(peer);
                peer = next;
            }
            f->releaseTreeMem(_codeAlloc);
            NJ_DELETE(f);
		}			

		verbose_only( enterCounts->clear();)
		verbose_only( mergeCounts->clear();)
		verbose_only( _stats.flushes++ );
		verbose_only( _stats.compiles = 0 );
	}

	AvmCore* Fragmento::core()
	{
		return _core;
	}

    Fragment* Fragmento::getAnchor(const void* ip)
	{
        Fragment *f = newFrag(ip);
        Fragment *p = _frags.get(ip);
        if (p) {
            f->first = p;
            /* append at the end of the peer list */
            Fragment* next;
            while ((next = p->peer) != NULL)
                p = next;
            p->peer = f;
        } else {
            f->first = f;
            _frags.put(ip, f); /* this is the first fragment */
        }
        f->anchor = f;
        f->root = f;
        f->kind = LoopTrace;
        f->mergeCounts = NJ_NEW(_core->gc, BlockHist)(_core->gc);
        verbose_only( addLabel(f, "T", _frags.size()); )
        return f;
	}
	
    Fragment* Fragmento::getLoop(const void* ip)
	{
        return _frags.get(ip);
	}

#ifdef NJ_VERBOSE
	void Fragmento::addLabel(Fragment *f, const char *prefix, int id)
	{
		char fragname[20];
		VMPI_sprintf(fragname,"%s%d", prefix, id);
		labels->add(f, sizeof(Fragment), 0, fragname);
	}
#endif

	Fragment *Fragmento::getMerge(GuardRecord *lr, const void* ip)
    {
		Fragment *anchor = lr->from->anchor;
		for (Fragment *f = anchor->branches; f != 0; f = f->nextbranch) {
			if (f->kind == MergeTrace && f->ip == ip /*&& f->calldepth == lr->calldepth*/) {
				// found existing shared branch on anchor
				return f;
			}
		}

		Fragment *f = newBranch(anchor, ip);
		f->root = f;
		f->kind = MergeTrace;
		f->calldepth = lr->calldepth;
		verbose_only(
			int mergeid = 1;
			for (Fragment *g = anchor->branches; g != 0; g = g->nextbranch)
				if (g->kind == MergeTrace)
					mergeid++;
			addLabel(f, "M", mergeid); 
		)
        return f;
    }

	Fragment *Fragmento::createBranch(GuardRecord *lr, const void* ip)
    {
		Fragment *from = lr->from;
        Fragment *f = newBranch(from, ip);
		f->kind = BranchTrace;
		f->calldepth = lr->calldepth;
		f->treeBranches = f->root->treeBranches;
		f->root->treeBranches = f;
        return f;
    }

	//
	// Fragment
	//
	Fragment::Fragment(const void* _ip) : ip(_ip), codeList(0)
	{
        // Fragment is a gc object which is zero'd by the GC, no need to clear fields
    }

	Fragment::~Fragment()
	{
        onDestroy();
    }
	
	void Fragment::addLink(GuardRecord* lnk)
	{
		//fprintf(stderr,"addLink %x from %X target %X\n",(int)lnk,(int)lnk->from,(int)lnk->target);
		lnk->next = _links;
		_links = lnk;
	}

	void Fragment::removeLink(GuardRecord* lnk)
	{
		GuardRecord*  lr = _links;
		GuardRecord** lrp = &_links;
		while(lr)
		{
			if (lr == lnk)
			{
				*lrp = lr->next;
				lnk->next = 0;
				break;
			}
			lrp = &(lr->next);
			lr = lr->next;
		}
	}
	
	void Fragment::link(Assembler* assm)
	{
		// patch all jumps into this fragment
		GuardRecord* lr = _links;
		while (lr)
		{
			GuardRecord* next = lr->next;
			Fragment* from = lr->target;
			if (from && from->fragEntry) assm->patch(lr);
			lr = next;
		}

		// and then patch all jumps leading out
		lr = outbound;
		while(lr)
		{
			GuardRecord* next = lr->outgoing;
			Fragment* targ = lr->target;
			if (targ && targ->fragEntry) assm->patch(lr);
			lr = next;
		}
	}

	void Fragment::unlink(Assembler* assm)
	{
		// remove our guards from others' in-bound list, so they don't patch to us 
		GuardRecord* lr = outbound;
		while (lr)
		{
			GuardRecord* next = lr->outgoing;
			Fragment* targ = lr->target;
			if (targ) targ->removeLink(lr);
			lr = next;
		}	

		// then unpatch all jumps into this fragment
		lr = _links;
		while (lr)
		{
			GuardRecord* next = lr->next;
			Fragment* from = lr->target;
			if (from && from->fragEntry) assm->unpatch(lr);
			lr = next;
		}
	}

#ifdef _DEBUG
	bool Fragment::hasOnlyTreeLinks()
	{
		// check that all incoming links are on the same tree
		bool isIt = true;
		GuardRecord *lr = _links;
		while (lr)
		{
			GuardRecord *next = lr->next;
			NanoAssert(lr->target == this);  // def'n of GuardRecord
			if (lr->from->root != root)
			{
				isIt = false;
				break;
			}
			lr = next;
		}	
		return isIt;		
	}
#endif

	void Fragment::removeIntraLinks()
	{
		// should only be called on root of tree
		NanoAssert(isRoot());
		GuardRecord *lr = _links;
		while (lr)
		{
			GuardRecord *next = lr->next;
			NanoAssert(lr->target == this);  // def'n of GuardRecord
			if (lr->from->root == root)
				removeLink(lr);
			lr = next;
		}	
	}
	
	void Fragment::unlinkBranches(Assembler* /*assm*/)
	{
		// should only be called on root of tree
		NanoAssert(isRoot());
		Fragment* frag = treeBranches;
		while(frag)
		{
			NanoAssert(frag->kind == BranchTrace && frag->hasOnlyTreeLinks());
			frag->_links = 0;
			frag->fragEntry = 0;
			frag = frag->treeBranches;
		}
	}

	void Fragment::linkBranches(Assembler* assm)
	{
		// should only be called on root of tree
		NanoAssert(isRoot());
		Fragment* frag = treeBranches;
		while(frag)
		{
			if (frag->fragEntry) frag->link(assm);
			frag = frag->treeBranches;
		}
	}
	
    void Fragment::blacklist()
    {
        blacklistLevel++;
        _hits = -(1<<blacklistLevel);
    }

    Fragment *Fragmento::newFrag(const void* ip)
    {
		GC *gc = _core->gc;
        Fragment *f = NJ_NEW(gc, Fragment)(ip);
		f->blacklistLevel = 5;
        return f;
    }

	Fragment *Fragmento::newBranch(Fragment *from, const void* ip)
	{
		Fragment *f = newFrag(ip);
		f->anchor = from->anchor;
		f->root = from->root;
		f->mergeCounts = from->anchor->mergeCounts;
        f->xjumpCount = from->xjumpCount;
		/*// prepend
		f->nextbranch = from->branches;
		from->branches = f;*/
		// append
		if (!from->branches) {
			from->branches = f;
		} else {
			Fragment *p = from->branches;
			while (p->nextbranch != 0)
				p = p->nextbranch;
			p->nextbranch = f;
		}
		return f;
	}

	void Fragment::releaseLirBuffer()
	{
		// tm removed this, why?
		if (lirbuf) {
			lirbuf->clear();
			lirbuf = 0;
			verbose_only(cfg = 0;)
		}
		lastIns = 0;	
	}

	void Fragment::releaseCode(CodeAlloc *codeAlloc)
	{
		_code = 0;
		codeAlloc->freeAll(codeList);
	}
	
	void Fragment::releaseTreeMem(CodeAlloc *codeAlloc)
	{
		releaseLirBuffer();
		releaseCode(codeAlloc);
			
		// now do it for all branches 
		Fragment* branch = branches;
		while(branch)
		{
			Fragment* next = branch->nextbranch;
			branch->releaseTreeMem(codeAlloc);  // @todo safer here to recurse in case we support nested trees
            NJ_DELETE(branch);
			branch = next;
		}
	}
	#endif /* FEATURE_NANOJIT */
}


