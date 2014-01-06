'''
    PONY junk code modification Script
    Copyright (c) 2012 Takahiro Haruyama
'''
def main():
    total_patched = 0

    for seg in idautils.Segments():
        segStart = idc.SegStart(seg)
        segEnd = idc.SegEnd(seg)
        if idc.SegName(segStart) == ".text":
            ea = segStart
            while ea != segEnd:
                ea = FindBinary(ea, SEARCH_DOWN, 'f8 72 01 c3 ff') # clc, jb, junc byte combination
                if ea == BADADDR:
                    break
                PatchDword(ea, 0x90909090)
                PatchByte(ea + 4, 0x90)
                PatchByte(ea - 5, 0xe9)
                addr = Dword(ea - 4)
                PatchDword(ea - 4, addr - ea)
                #DelFunction(addr)
                MakeUnknown(addr, 0x10, DOUNK_SIMPLE)
                MakeCode(addr)
                #funcStart = GetFunctionAttr(ea, FUNCATTR_START)
                #MakeFunction(funcStart)

                print "patched at %08X" % ea
                total_patched += 1
                ea = NextHead(ea, segEnd)


    print "%d times patched" % total_patched
    AnalyzeArea(segStart, segEnd)
    Refresh()

if __name__ == '__main__':
    main()