rule sig_20160312_8437c95aa032e8dca6e8ea7a87899ae9 {
  meta:
    description = "datamaliciousorder - file 20160312_8437c95aa032e8dca6e8ea7a87899ae9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93abfe18ac2ba907cbf83e05be19f6a61f2866a2fad4986ad0e4cca3f3f4b85a"

  strings:
    $s1  = "return NlOcBFy[0] + NlOcBFy[2] + NlOcBFy[4] + \".F\" + NlOcBFy[7] + NlOcBFy[9] + NlOcBFy[12] + NlOcBFy[14];" fullword ascii
    $s2  = "var ng = true  , URZR = FhX[7] + FhX[9] + FhX[11];" fullword ascii
    $s3  = "oEMYa.open(kfJiu,FvAnM,false);" fullword ascii
    $s4  = "var NlOcBFy = \"Sc YRvdaSI r KbMPKkjXO ipting RycYDiG Oqk ile WxBEJuhtJbUVvk System Bx xpqEf Obj lEWBoA ect EFAlvab\".split(\" " ascii
    $s5  = "var FhX = (\"2.XMLHTTP TDmhqwU wruCc XML ream St BWsYOTTe AD xaItUGr O cgCf D\").split(\" \");" fullword ascii
    $s6  = "if(S>=O.length) {break;}" fullword ascii
    $s7  = "function ESkW(jjhpq) {" fullword ascii
    $s8  = "if (MJMGc > 172865-681){return true;} else {return false;}" fullword ascii
    $s9  = "function vJJkP(MIiSVI) {" fullword ascii
    $s10 = "function kkXOL(vUMasA) {" fullword ascii
    $s11 = "function UqTg(UuIFe) {" fullword ascii
    $s12 = "function sOug(aXebj,FFoaM) {" fullword ascii
    $s13 = "function vquU(FniAA) {" fullword ascii
    $s14 = "return peDAhCH" fullword ascii
    $s15 = "function gERnGLtBo() {" fullword ascii
    $s16 = "function NshV(oEMYa,FvAnM,kfJiu) {" fullword ascii
    $s17 = "return jkdnqbi(jy,amBgk[181-175]+amBgk[795-788]+amBgk[640-632]);" fullword ascii
    $s18 = "return lZqYi;" fullword ascii
    $s19 = "if (u >= FniAA.length) {break;}" fullword ascii
    $s20 = "function KtahNhp(GDuc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}