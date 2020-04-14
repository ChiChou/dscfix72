from dsc_fix import Symbols

if __name__ == "__main__":

    import sys
    s = Symbols(sys.argv[1])
    s.load()

    print(s.fast(0x1C64209A8))
    print(s.locate(0x1C64209A8))
    print(s.segments['/usr/lib/libobjc.A.dylib']['__OBJC_RO'])
