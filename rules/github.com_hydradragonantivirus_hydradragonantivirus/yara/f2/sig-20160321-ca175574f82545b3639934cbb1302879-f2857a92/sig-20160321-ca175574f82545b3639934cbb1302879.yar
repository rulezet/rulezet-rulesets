rule sig_20160321_ca175574f82545b3639934cbb1302879 {
  meta:
    description = "datamaliciousorder - file 20160321_ca175574f82545b3639934cbb1302879.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "757bff2f2b3456dafe1558e2f0c980c744d0a635e6bb06218d52928c45e7e0d4"

  strings:
    $s1  = "return WScript.CreateObject(eaFZf);" fullword ascii
    $s2  = "return tDdnanp[0] + tDdnanp[2] + tDdnanp[4] + \".F\" + tDdnanp[7] + tDdnanp[9] + tDdnanp[12] + tDdnanp[14];" fullword ascii
    $s3  = "var Sw = true  , QWIf = FPf[7] + FPf[9] + FPf[11];" fullword ascii
    $s4  = "SzRsK.open(mwGuI,Iihrd,false);" fullword ascii
    $s5  = "var tDdnanp = dpdcG(zmPPixycla+\" \"+\"System kQ CQlzM Obj FcposP ect LVbAvTG wToHm\", \" \");" fullword ascii
    $s6  = "var FPf = (\"2.XMLHTTP VCplWPy zYqoX XML ream St eCrAybMW AD qSjivfs O AYiu D\").split(\" \");" fullword ascii
    $s7  = "if (TDlrz == 406-206){return true;} else {return false;}" fullword ascii
    $s8  = "function pLWZNiD(GXUM,xprqS) {" fullword ascii
    $s9  = "return uSFtk.status;" fullword ascii
    $s10 = "function xMEUS(DoqMiy) {" fullword ascii
    $s11 = "function LOtD(MzBiJ,beTqX) {" fullword ascii
    $s12 = "return lEUo[olHfEM[0]];" fullword ascii
    $s13 = "function SdKRbOOcj(UVHTmwcczsn) {" fullword ascii
    $s14 = "return aCd.size;" fullword ascii
    $s15 = "function aizv(TDlrz) {" fullword ascii
    $s16 = "if(W>=Z.length) {break;}" fullword ascii
    $s17 = "return KQweg;" fullword ascii
    $s18 = "function BPIFJNig(aCd) {" fullword ascii
    $s19 = "return pLWZNiD(Wy,jXqfW[954-948]+jXqfW[353-346]+jXqfW[565-557]);" fullword ascii
    $s20 = "Zkv = W; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}