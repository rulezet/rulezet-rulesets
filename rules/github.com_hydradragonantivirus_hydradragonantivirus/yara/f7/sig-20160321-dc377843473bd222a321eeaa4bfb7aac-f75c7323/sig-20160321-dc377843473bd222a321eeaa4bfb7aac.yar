rule sig_20160321_dc377843473bd222a321eeaa4bfb7aac {
  meta:
    description = "datamaliciousorder - file 20160321_dc377843473bd222a321eeaa4bfb7aac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "855787e7dae5f291eb52306b84bc96936bfa7597974c307ec55c25de9ac48b31"

  strings:
    $s1  = "return WScript.CreateObject(lMPTR);" fullword ascii
    $s2  = "var zc = true  , NpLL = fmi[7] + fmi[9] + fmi[11];" fullword ascii
    $s3  = "return rHNCmTH[0] + rHNCmTH[2] + rHNCmTH[4] + \".F\" + rHNCmTH[7] + rHNCmTH[9] + rHNCmTH[12] + rHNCmTH[14];" fullword ascii
    $s4  = "WvDzD.open(XWQmG,tEcMM,false);" fullword ascii
    $s5  = "var fmi = (\"2.XMLHTTP UhcxluH hIxqC XML ream St qunkOnjS AD xxNAchV O qCEK D\").split(\" \");" fullword ascii
    $s6  = "var rHNCmTH = nOKaL(xeDIdKPgZs+\" \"+\"System yM yXjVy Obj diBlaR ect ihEKTPv FDutW\", \" \");" fullword ascii
    $s7  = "nFu = D; break; " fullword ascii
    $s8  = "function QufOsbLo(jjfJ) {" fullword ascii
    $s9  = "return aJnWz.status;" fullword ascii
    $s10 = "return wLChXDx(Dt,rhyuW[443-437]+rhyuW[654-647]+rhyuW[664-656]);" fullword ascii
    $s11 = "function jYIG(lMPTR) {" fullword ascii
    $s12 = "function IYtQ(WvDzD,tEcMM,XWQmG) {" fullword ascii
    $s13 = "if (FmzwH > 187340-222){return true;} else {return false;}" fullword ascii
    $s14 = "return zOa.size;" fullword ascii
    $s15 = "if(D>=R.length) {break;}" fullword ascii
    $s16 = "return lwrQ[LOBrxA[0]];" fullword ascii
    $s17 = "function NujO(FmzwH) {" fullword ascii
    $s18 = "function YaMrN(HLwEvv) {" fullword ascii
    $s19 = "if (MLhkr == 910-710){return true;} else {return false;}" fullword ascii
    $s20 = "function wYGZ(MLhkr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}