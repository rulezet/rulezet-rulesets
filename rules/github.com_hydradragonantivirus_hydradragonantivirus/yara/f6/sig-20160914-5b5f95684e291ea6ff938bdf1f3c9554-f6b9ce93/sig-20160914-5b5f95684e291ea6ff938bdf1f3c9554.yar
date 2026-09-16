rule sig_20160914_5b5f95684e291ea6ff938bdf1f3c9554 {
  meta:
    description = "datamaliciousorder - file 20160914_5b5f95684e291ea6ff938bdf1f3c9554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d8693483b51bf68e27d2b4911e1d4597f511b71a081c79ba831586a56a03932"

  strings:
    $s1  = "function XXe(OwM, vde, Xu, RhI)" fullword ascii
    $s2  = "return JHp;" fullword ascii
    $s3  = "while (p < SAv)" fullword ascii
    $s4  = "function UC(OwM)" fullword ascii
    $s5  = "function ou(Wn)" fullword ascii
    $s6  = "return eval(fP);" fullword ascii
    $s7  = "return AnY(ie, vde, Xu, nmr);" fullword ascii
    $s8  = "function q(lY)" fullword ascii
    $s9  = "return (NM(Jxe, vde));" fullword ascii
    $s10 = "return MA;" fullword ascii
    $s11 = "function AnY(dx, vde, Xu, RhI)" fullword ascii
    $s12 = "return KnO == Fkl;" fullword ascii
    $s13 = "return (XXe(Jxe, vde, Xu, RhI));" fullword ascii
    $s14 = "return HF;" fullword ascii
    $s15 = "function uuv(Idk)" fullword ascii
    $s16 = "return (UC(Jxe));" fullword ascii
    $s17 = "function QPz(xMv, V)" fullword ascii
    $s18 = "var fP = String[g](DPZ);" fullword ascii
    $s19 = "function NM(OwM, vde)" fullword ascii
    $s20 = "return XXe(OPB, vde, Xu, RhI);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}