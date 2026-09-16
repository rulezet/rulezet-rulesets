rule sig_20160321_0cb9df5f902eaffc9eb2197c6fc8f4d5 {
  meta:
    description = "datamaliciousorder - file 20160321_0cb9df5f902eaffc9eb2197c6fc8f4d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "973a447d627207cbcccab7aabf13efa866a0792520aa1e4d4fdac3b6902277ff"

  strings:
    $s1  = "return WScript.CreateObject(CzTwd);" fullword ascii
    $s2  = "return WoxLaZq[0] + WoxLaZq[2] + WoxLaZq[4] + \".F\" + WoxLaZq[7] + WoxLaZq[9] + WoxLaZq[12] + WoxLaZq[14];" fullword ascii
    $s3  = "var Xj = true  , oznw = Ifk[7] + Ifk[9] + Ifk[11];" fullword ascii
    $s4  = "RiVhD.open(YavdT,ZRHBj,false);" fullword ascii
    $s5  = "var Ifk = (\"2.XMLHTTP ZZLonkD JKhpg XML ream St knEzALwk AD MvSCEbZ O YGKm D\").split(\" \");" fullword ascii
    $s6  = "var WoxLaZq = DDMWv(oSACwlPZRZ+\" \"+\"System IG CIVmg Obj YeWPKU ect aEsFQYF ogFSs\", \" \");" fullword ascii
    $s7  = "function QIYMZjGEH(AxBEhNjbekj) {" fullword ascii
    $s8  = "function atFjzsd(AtRK) {" fullword ascii
    $s9  = "if (SoRHx == 859-659){return true;} else {return false;}" fullword ascii
    $s10 = "function hJar(wKsbK,biBrO) {" fullword ascii
    $s11 = "function zeqNR(xwetlV) {" fullword ascii
    $s12 = "return GgS.size;" fullword ascii
    $s13 = "function fRfp(gGlBX) {" fullword ascii
    $s14 = "DzTO(Sc,idvjm+m[g]+c, GZa[12]+GZa[14]+GZa[16]); PAlp(Sc); " fullword ascii
    $s15 = "return AtRK[FuqLne[0]];" fullword ascii
    $s16 = "return DRbdS;" fullword ascii
    $s17 = "RxA = g; break; " fullword ascii
    $s18 = "function ASwp(SoRHx) {" fullword ascii
    $s19 = "return new ActiveXObject(zwVSnH);" fullword ascii
    $s20 = "return rDQXlcb(fZ,sdlCH[256-250]+sdlCH[211-204]+sdlCH[410-402]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}