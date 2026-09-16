rule sig_20160312_eb694e1d9cecd95475c48d5d1c68c921 {
  meta:
    description = "datamaliciousorder - file 20160312_eb694e1d9cecd95475c48d5d1c68c921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53bae8c95d594cbf88e217e8729c850a1a8efaad5f78877693f5ce002aaf0924"

  strings:
    $s1  = "GxWAH.open(AUiPN,oSruN,false);" fullword ascii
    $s2  = "return WpYUYFe[0] + WpYUYFe[2] + WpYUYFe[4] + \".F\" + WpYUYFe[7] + WpYUYFe[9] + WpYUYFe[12] + WpYUYFe[14];" fullword ascii
    $s3  = "var Fw = true  , kegv = Gpl[7] + Gpl[9] + Gpl[11];" fullword ascii
    $s4  = "var Gpl = (\"2.XMLHTTP UtxDOin SihkF XML ream St xaWpsmxU AD OInwjvf O gnVo D\").split(\" \");" fullword ascii
    $s5  = "function iOWR(GxWAH,oSruN,AUiPN) {" fullword ascii
    $s6  = "function KRejFZRSg(PrJqacIJhRz) {" fullword ascii
    $s7  = "return new ActiveXObject(fstprh);" fullword ascii
    $s8  = "function qCUBJmEP() {" fullword ascii
    $s9  = "function llLUyDJ(WOXu,pQlLD) {" fullword ascii
    $s10 = "function uAXQ(ROUCj,SMiLI) {" fullword ascii
    $s11 = "function LWwJ(LDRWx) {" fullword ascii
    $s12 = "function zkYY(kJHwU) {" fullword ascii
    $s13 = "function OAWg(slGiG,CbGDr) {" fullword ascii
    $s14 = "if (T >= LDRWx.length) {break;}" fullword ascii
    $s15 = "krO = S; break; " fullword ascii
    $s16 = "function cogGmGO(gGTz) {" fullword ascii
    $s17 = "return QgDjhoR" fullword ascii
    $s18 = "return jHSXq.status;" fullword ascii
    $s19 = "return awGoqI.position=778-778;" fullword ascii
    $s20 = "function TkUFhbTbx() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}