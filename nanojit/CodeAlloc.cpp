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

#include "nanojit.h"

#ifdef FEATURE_NANOJIT

namespace nanojit
{
    static const bool verbose = false;
    static const int pagesPerAlloc = 1;
    static const int bytesPerAlloc = pagesPerAlloc * GCHeap::kBlockSize;

    CodeAlloc::CodeAlloc(GC* gc)
        : heap(gc->GetGCHeap()), freelist(0), heapblocks(gc)
    {}

    CodeAlloc::~CodeAlloc() {
        // give all memory back to gcheap.  Assumption is that all
        // code is done being used by now.
        for (int i=0, n=heapblocks.size(); i < n; i++)
            heap->Free(heapblocks[i]);
    }

    int CodeAlloc::totalSize() {
        return heapblocks.size() * bytesPerAlloc;
    }

    void CodeAlloc::alloc(NIns* &start, NIns* &end) {
        if (!freelist) {
            void *mem = heap->Alloc(pagesPerAlloc, /* expand */ true);  // allocations never fail
            markExecutable(mem, bytesPerAlloc);
            heapblocks.add(mem);
            addMem(freelist, mem, bytesPerAlloc);
            if (verbose)
                avmplus::AvmLog("heapalloc %p total=%d\n", mem, totalSize());
        }
        CodeList* b = removeBlock(freelist);
        start = b->start();
        end = b->end;
        if (verbose)
            avmplus::AvmLog("alloc %p-%p %d\n", start, end, int(end-start));
    }

    void CodeAlloc::free(NIns* start, NIns *end) {
        CodeList *b = getBlock(start, end);
        size_t size = b->size();
        if (verbose)
            avmplus::AvmLog("free %p-%p %d\n", start, end, (int)size);
        memset(start, 0xCC, size); // INT 3 instruction
        add(freelist, start, end);
    }

    void CodeAlloc::freeAll(CodeList* &code) {
        while (code) {
            CodeList *b = removeBlock(code);
            free(b->start(), b->end);
        }
    }

#if defined(AVMPLUS_UNIX) && defined(NANOJIT_ARM)
#include <asm/unistd.h>
extern "C" void __clear_cache(char *BEG, char *END);
#endif

#ifdef AVMPLUS_SPARC
extern  "C"	void sync_instruction_memory(caddr_t v, u_int len);
#endif

#if defined NANOJIT_IA32 || defined NANOJIT_X64
    // intel chips have dcache/icache interlock
	void CodeAlloc::flushICache(CodeList* &)
    {}

#elif defined NANOJIT_ARM && defined UNDER_CE
    // on arm/winmo, just flush the whole icache
    // fixme: why?
	void CodeAlloc::flushICache(CodeList* &) {
		// just flush all of it
		FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    }

#elif defined AVMPLUS_MAC && defined NANOJIT_PPC

#  ifdef NANOJIT_64BIT
    extern "C" void sys_icache_invalidate(const void*, size_t len);
    extern "C" void sys_dcache_flush(const void*, size_t len);

    // mac 64bit requires 10.5 so use that api
	void CodeAlloc::flushICache(CodeList* &blocks) {
        for (CodeList *b = blocks; b != 0; b = b->next) {
            void *start = b->start();
            size_t bytes = b->size();
            sys_dcache_flush(start, bytes);
            sys_icache_invalidate(start, bytes);
		}
    }
#  else
    // mac ppc 32 could be 10.0 or later
    // uses MakeDataExecutable() from Carbon api, OSUtils.h
    // see http://developer.apple.com/documentation/Carbon/Reference/Memory_Manag_nt_Utilities/Reference/reference.html#//apple_ref/c/func/MakeDataExecutable
	void CodeAlloc::flushICache(CodeList* &blocks) {
        for (CodeList *b = blocks; b != 0; b = b->next)
            MakeDataExecutable(b->start(), b->size());
    }
#  endif

#elif defined AVMPLUS_SPARC
    // fixme: sync_instruction_memory is a solaris api, test for solaris not sparc
	void CodeAlloc::flushICache(CodeList* &blocks) {
        for (CodeList *b = blocks; b != 0; b = b->next)
                       sync_instruction_memory((char*)b->start(), b->size());
    }

#elif defined NANOJIT_UNIX
    // fixme: __clear_cache is a libgcc feature, test for libgcc or gcc 
	void CodeAlloc::flushICache(CodeList* &blocks) {
        FIXME
		Page *p = pages;
		Page *first = p;
		while (p) {
			if (!p->next || p->next != p+1) {
				__clear_cache((char*)first, (char*)(p+1));
				first = p->next;
			}
			p = p->next;
		}
    }
#endif // AVMPLUS_MAC && NANOJIT_PPC

    void CodeAlloc::addBlock(CodeList* &blocks, CodeList* b) {
        b->next = blocks;
        blocks = b;
    }

    void CodeAlloc::addMem(CodeList* &blocks, void *mem, size_t bytes) {
        CodeList* b = (CodeList*)mem;
        b->end = (NIns*) (uintptr_t(mem) + bytes);
        b->next = 0;
        addBlock(blocks, b);
    }

    CodeList* CodeAlloc::getBlock(NIns* start, NIns* end) {
        CodeList* b = (CodeList*) (uintptr_t(start) - offsetof(CodeList, code));
        NanoAssert(b->end == end && b->next == 0); (void) end;
        return b;
    }

    CodeList* CodeAlloc::removeBlock(CodeList* &blocks) {
        CodeList* b = blocks;
        blocks = b->next;
        b->next = 0;
        return b;
    }

    void CodeAlloc::add(CodeList* &blocks, NIns* start, NIns* end) {
        addBlock(blocks, getBlock(start, end));
    }

    /**
     * split a block by freeing the hole in the middle defined by [holeStart,holeEnd),
     * and adding the used prefix and suffix parts to the blocks CodeList.
     */
    void CodeAlloc::addRemainder(CodeList* &blocks, NIns* start, NIns* end, NIns* holeStart, NIns* holeEnd) {
        NanoAssert(start < end && start <= holeStart && holeStart <= holeEnd && holeEnd <= end);
        // shrink the hole by aligning holeStart forward and holeEnd backward
        holeStart = (NIns*) alignUp(holeStart, sizeof(NIns*));
        holeEnd = (NIns*) alignTo(holeEnd, sizeof(NIns*));
        if (uintptr_t(holeEnd) - uintptr_t(holeStart) < 2 * sizeofMinBlock) {
            // the hole is too small to make a new free block and a new used block. just keep
            // the whole original block and don't free anything.
            add(blocks, start, end);
        } else if (holeStart == start && holeEnd == end) {
            // totally empty block.  free whole start-end range
            this->free(start, end);
        } else if (holeStart == start) {
            // hole is left-aligned with start, so just need one new block
            CodeList* b1 = getBlock(start, end);
            CodeList* b2 = (CodeList*) (uintptr_t(holeEnd) - offsetof(CodeList, code));
            b1->end = (NIns*) b2;
            b2->end = end;
            b2->next = 0;
            this->free(b1->start(), b1->end);
            addBlock(blocks, b2);
        } else if (holeEnd == end) {
            // hole is right-aligned with end, just need one new block
            // todo
            NanoAssert(false);
        } else {
            // there's enough space left to split into three blocks (two new ones)
            CodeList* b1 = getBlock(start, end);
            CodeList* b2 = (CodeList*) holeStart;
            CodeList* b3 = (CodeList*) (uintptr_t(holeEnd) - offsetof(CodeList, code));
            b1->end = (NIns*) b2;
            b2->end = (NIns*) b3;
            b3->end = end;
            b2->next = 0;
            b3->next = 0;
            this->free(b2->start(), b2->end);
            addBlock(blocks, b3);
            addBlock(blocks, b1);
        }
    }

    size_t CodeAlloc::size(const CodeList* blocks) {
        size_t size = 0;
        for (const CodeList* b = blocks; b != 0; b = b->next)
            size += b->size();
        return size;
    }

    bool CodeAlloc::contains(const CodeList* blocks, NIns* p) {
        for (const CodeList *b = blocks; b != 0; b = b->next) {
            if (b->contains(p))
                return true;
        }
        return false;
    }

    void CodeAlloc::moveAll(CodeList* &blocks, CodeList* &other) {
        if (other) {
            CodeList* last = other;
            while (last->next)
                last = last->next;
            last->next = blocks;
            blocks = other;
            other = 0;
        }
    }

    // figure out whether this is a pointer into allocated/free code,
    // or something we don't manage.
    CodeAlloc::CodePointerKind CodeAlloc::classifyPtr(NIns *p) {
        for (int i=0, n = heapblocks.size(); i < n; i++) {
            if (containsPtr((NIns*)heapblocks[i], (NIns*)((uintptr_t)heapblocks[i]+bytesPerAlloc), p)) {
                return contains(freelist, p) ? kFree : kUsed;
            }
        }
        return kUnknown;
    }    

#if defined AVMPLUS_MAC || defined AVMPLUS_UNIX || defined SOLARIS
    // use mprotect generic unix api (posix?)
	void CodeAlloc::markExecutable(void *mem, size_t bytes) {
        if (mprotect((char*)mem, bytes, PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
            // todo: we can't abort or assert here, we have to fail gracefully.
            NanoAssertMsg(false, "FATAL ERROR: mprotect(PROT_EXEC) failed\n");
            abort();
        }
	}

#elif defined WIN32
	void CodeAlloc::markExecutable(void *mem, size_t bytes)
	{
		DWORD dwIgnore;
		if (!VirtualProtect(mem, bytes, PAGE_EXECUTE_READWRITE, &dwIgnore)) {
			// todo: we can't abort or assert here, we have to fail gracefully.
			NanoAssertMsg(false, "FATAL ERROR: VirtualProtect() failed\n");
		}
    }
#endif
}
#endif // FEATURE_NANOJIT
