rule sig_20160428_2d39f91ead1c6e29e15fcabe4e0d41b6 {
  meta:
    description = "datamaliciousorder - file 20160428_2d39f91ead1c6e29e15fcabe4e0d41b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7a7dfc889187306390d9acf2fe56d988934f326e0e26d6f2cc2e343694867ad"

  strings:
    $s1  = "while (RVEqLo < ptiz - (5841, 2734, 7402, 7584, 5704, 2)) {" fullword ascii
    $s2  = "return oPB + zlIzJVIk + BgIjE + ILB + pHFqXYsb + iClH;" fullword ascii
    $s3  = "if (ppVa === false) {" fullword ascii
    $s4  = "return iQNL[DzEelquo];" fullword ascii
    $s5  = "function ctbjU(rQi) {" fullword ascii
    $s6  = "return ePd;" fullword ascii
    $s7  = "function BwPf(fbwcGa) {" fullword ascii
    $s8  = "if (ctbjU(1) != true) {" fullword ascii
    $s9  = "fAdE = fAdE / HKGKzm;" fullword ascii
    $s10 = "function juTK() {" fullword ascii
    $s11 = "return sfawVeSS;" fullword ascii
    $s12 = "return oIv;" fullword ascii
    $s13 = "function fTT(UVyxa, VKVTfics) {" fullword ascii
    $s14 = "function rDPhDbL(DzEelquo) {" fullword ascii
    $s15 = "var DJavYD = false;" fullword ascii
    $s16 = "function ADVq(fJUrapF) {" fullword ascii
    $s17 = "if (DJavYD == true) {" fullword ascii
    $s18 = "var wJNdLEO = true;;" fullword ascii
    $s19 = "function czmC() {" fullword ascii
    $s20 = "var TtKJyuD = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}