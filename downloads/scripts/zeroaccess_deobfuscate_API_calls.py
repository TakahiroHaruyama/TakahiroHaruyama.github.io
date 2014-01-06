'''
    ZeroAccess Deobfuscation Script
    Copyright (c) 2012 Takahiro Haruyama
'''
resolve_funcs = ["cci_resolve_func_from_ntdll", "cci_resolve_func_from_ntdll_0", "cci_resolve_func_from_ntdll_1"]

def main():
    for seg in idautils.Segments():
        segStart = idc.SegStart(seg)
        segEnd = idc.SegEnd(seg)
        if idc.SegName(segStart) == ".text":
            ea = segStart
            while ea != segEnd:
                ea = FindBinary(ea, SEARCH_DOWN, 'f8 72 01 c3 ff')
                if ea == BADADDR:
                    break
                print "deobfuscated call at %08X" % ea
                ea = NextHead(ea, segEnd)

if __name__ == '__main__':
    main()
