rule sig_20160404_ae976f6dd868b8890e21892394b0bbfb {
  meta:
    description = "datamaliciousorder - file 20160404_ae976f6dd868b8890e21892394b0bbfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6604749c12e613b9f4a61c152abe414d66474dbd5a987b88c4efae051f690710"

  strings:
    $s1  = "var HD = true  , PIXg = cQU[7] + cQU[9] + cQU[11];" fullword ascii
    $s2  = "return oaRLEiY[0] + oaRLEiY[2] + oaRLEiY[4] + \".F\" + oaRLEiY[7] + oaRLEiY[9] + oaRLEiY[12] + oaRLEiY[14];" fullword ascii
    $s3  = "var cQU = (\"2.XMLHTTP YkRPCCG YlXIG XML ream St KcrVWfcZ AD SClDRjm O PnfG D\").split(\" \");" fullword ascii
    $s4  = "Rbho.open(Lmxvx,wRLGo,false);" fullword ascii
    $s5  = "var oaRLEiY = brprc(lgSznhQxyJ+\" \"+\"System cU YpQYe Obj suRMoN ect bzGYxIW tHFDo\", \" \");" fullword ascii
    $s6  = "if(D>=V.length) {break;}" fullword ascii
    $s7  = "function xZAe(GKvKg,aNhUb) {" fullword ascii
    $s8  = "function YvgnBY(DmKSjrA) {" fullword ascii
    $s9  = "if (N >= iIzVB.length) {break;}" fullword ascii
    $s10 = "function NQhqGbi(ZioY,KOaGm) {" fullword ascii
    $s11 = "function FyIp(GOUtb,yJbOr) {" fullword ascii
    $s12 = "function YXUWdhq(ClCu) {" fullword ascii
    $s13 = "if (YaZjo == 496-296){return true;} else {return false;}" fullword ascii
    $s14 = "function bGRGpWWU(PlLb) {" fullword ascii
    $s15 = "return aNq.size;" fullword ascii
    $s16 = "function jjaQG(NJmgUv) {" fullword ascii
    $s17 = "function XXOB(ZKOcW) {" fullword ascii
    $s18 = "return NQhqGbi(XM,KUQQe[385-379]+KUQQe[442-435]+KUQQe[351-343]);" fullword ascii
    $s19 = "return aBRgu;" fullword ascii
    $s20 = "if (ZWBQb > 152961-304){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}