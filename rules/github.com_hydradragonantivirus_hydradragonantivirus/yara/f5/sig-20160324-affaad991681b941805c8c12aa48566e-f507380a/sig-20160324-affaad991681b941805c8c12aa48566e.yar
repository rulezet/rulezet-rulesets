rule sig_20160324_affaad991681b941805c8c12aa48566e {
  meta:
    description = "datamaliciousorder - file 20160324_affaad991681b941805c8c12aa48566e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cafc8ded03d16fd6bda2d30564f158bb890c35dcb9aa118a7609123dccd5a1c6"

  strings:
    $s1  = "return WScript.CreateObject(xlQEn);" fullword ascii
    $s2  = "var dFU = (\"2.XMLHTTP cNdEOXJ QMMNr XML ream St RFrPAssf AD uiJFLmg O rXBP D\").split(\" \");" fullword ascii
    $s3  = "var sV = true  , kVYM = dFU[7] + dFU[9] + dFU[11];" fullword ascii
    $s4  = "return RxbzRys[0] + RxbzRys[2] + RxbzRys[4] + \".F\" + RxbzRys[7] + RxbzRys[9] + RxbzRys[12] + RxbzRys[14];" fullword ascii
    $s5  = "IDXn.open(eJifJ,hjfbg,false);" fullword ascii
    $s6  = "var RxbzRys = daaoO(pvDjPIeXWF+\" \"+\"System JU sigIw Obj EBETFk ect YFJCUUH OjDgj\", \" \");" fullword ascii
    $s7  = "return bUYB.ExpandEnvironmentStrings(mcgMg);" fullword ascii
    $s8  = "function gLlZ(mYhFK) {" fullword ascii
    $s9  = "return tKhYwx/*PiLSf7hy7QoYIcFYoeXJvw7KZ*/.position=918-918;" fullword ascii
    $s10 = "function qUmvmrhR(Hjg) {" fullword ascii
    $s11 = "function LIoIH(tKhYwx) {" fullword ascii
    $s12 = "function mPCGYfb(bUYB,mcgMg) {" fullword ascii
    $s13 = "function XpbE(KmOKO) {" fullword ascii
    $s14 = "return KmOKO.status;" fullword ascii
    $s15 = "return LPIx[GXySXo[0]];" fullword ascii
    $s16 = "if (MWSWR == 783-583){return true;} else {return false;}" fullword ascii
    $s17 = "if(B>=s.length) {break;}" fullword ascii
    $s18 = "function wNQo(xlQEn) {" fullword ascii
    $s19 = "function qPtS(xTvTn,hYJJt) {" fullword ascii
    $s20 = "Alr = B; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}