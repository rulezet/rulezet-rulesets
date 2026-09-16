rule sig_20160323_d576ced3c004fc0e23ba1f3ca4097b6e {
  meta:
    description = "datamaliciousorder - file 20160323_d576ced3c004fc0e23ba1f3ca4097b6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffffe9b27b5be50511754806c978878ef30a7f4ad2c4d15ee4ba48fc05c80934"

  strings:
    $s1  = "return WScript.CreateObject(oQwLG);" fullword ascii
    $s2  = "var yp = true  , vvLP = Zmg[7] + Zmg[9] + Zmg[11];" fullword ascii
    $s3  = "return lnZBsiH[0] + lnZBsiH[2] + lnZBsiH[4] + \".F\" + lnZBsiH[7] + lnZBsiH[9] + lnZBsiH[12] + lnZBsiH[14];" fullword ascii
    $s4  = "JASj.open(BqssL,WlJtB,false);" fullword ascii
    $s5  = "var lnZBsiH = gBLHE(AnxzqvJIHI+\" \"+\"System LD ByyNs Obj JvFQud ect XLvYfOA xqUoD\", \" \");" fullword ascii
    $s6  = "var Zmg = (\"2.XMLHTTP gokxPDh mHvvg XML ream St tuIGFOnF AD DacuQgi O qSGK D\").split(\" \");" fullword ascii
    $s7  = "if (YNXwf == 315-115){return true;} else {return false;}" fullword ascii
    $s8  = "return ihfCu.status;" fullword ascii
    $s9  = "function MkIxLhF(vLjq) {" fullword ascii
    $s10 = "function xCGc(YNXwf) {" fullword ascii
    $s11 = "function Gueo(oQwLG) {" fullword ascii
    $s12 = "function YUzNdpa(UjdH,XzAWO) {" fullword ascii
    $s13 = "return UjdH.ExpandEnvironmentStrings(XzAWO);" fullword ascii
    $s14 = "return new ActiveXObject(TwOa);" fullword ascii
    $s15 = "function pacTI(FKqzvk) {" fullword ascii
    $s16 = "return JdERR;" fullword ascii
    $s17 = "function XagTkerd(EGJM) {" fullword ascii
    $s18 = "function Qomy(ihfCu) {" fullword ascii
    $s19 = "if(T>=o.length) {break;}" fullword ascii
    $s20 = "return vLjq[OaVvhx[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}