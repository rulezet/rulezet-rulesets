rule sig_20160314_33a9f724fbf9921f94a980305a2d0558 {
  meta:
    description = "datamaliciousorder - file 20160314_33a9f724fbf9921f94a980305a2d0558.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e6634c93fbab07d6ee817d63c5d4c0db887b32bacc257bb9426b3c1db00f953"

  strings:
    $s1  = "return zPivieA[0] + zPivieA[2] + zPivieA[4] + \".F\" + zPivieA[7] + zPivieA[9] + zPivieA[12] + zPivieA[14];" fullword ascii
    $s2  = "var mU = true  , FAie = yCc[7] + yCc[9] + yCc[11];" fullword ascii
    $s3  = "gtnTn.open(Gtjwr,GTTCz,false);" fullword ascii
    $s4  = "var yCc = (\"2.XMLHTTP ATWyKvO yxIkt XML ream St QdLPhZCG AD BZaundP O mTkO D\").split(\" \");" fullword ascii
    $s5  = "return yGBUNdw(vR,WdRXN[256-250]+WdRXN[576-569]+WdRXN[615-607]);" fullword ascii
    $s6  = "function hhacYOdCi(uvSIn) {" fullword ascii
    $s7  = "function lPOg(AvMJH) {" fullword ascii
    $s8  = "function QIdv(ULlef,ohUWG) {" fullword ascii
    $s9  = "function DjhX(pGiRW) {" fullword ascii
    $s10 = "return KLmms.status;" fullword ascii
    $s11 = "return lnl.split(AmdIN);" fullword ascii
    $s12 = "if (i >= grsTu.length) {break;}" fullword ascii
    $s13 = "return OooP.ExpandEnvironmentStrings(XdpuV);" fullword ascii
    $s14 = "return deW.size;" fullword ascii
    $s15 = "function JGQa(njArP) {" fullword ascii
    $s16 = "if(k>=X.length) {break;}" fullword ascii
    $s17 = "function gWxe(XBnbl,Kaqvy) {" fullword ascii
    $s18 = "function jVcbx(YIuKgR) {" fullword ascii
    $s19 = "return zrDecXw" fullword ascii
    $s20 = "function gUfMrHRa() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}