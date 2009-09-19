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


#ifndef __nanojit_Fragmento__
#define __nanojit_Fragmento__

namespace nanojit
{
    struct GuardRecord;

    /**
     * Fragments are linear sequences of native code that have a single entry
     * point at the start of the fragment and may have one or more exit points
     *
     * It may turn out that that this arrangement causes too much traffic
     * between d and i-caches and that we need to carve up the structure differently.
     */
    class Fragment
    {
        public:
            Fragment(const void*);
            ~Fragment();

            NIns*           code()                          { return _code; }
            void            setCode(NIns* codee)            { _code = codee; }
            GuardRecord*    links()                         { return _links; }
            bool            isRoot() { return root == this; }

            Fragment*      root;
            LirBuffer*     lirbuf;
            LIns*          lastIns;

            const void* ip;
            NIns* fragEntry;
            int32_t calldepth;
            void* vmprivate;

        private:
            NIns*           _code;      // ptr to start of code
            GuardRecord*    _links;     // code which is linked (or pending to be) to this fragment
            int32_t         _hits;
    };
}
#endif // __nanojit_Fragmento__
