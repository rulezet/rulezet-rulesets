rule sig_20160324_15967f95b79b4ea0cc58b218fb37003e {
  meta:
    description = "datamaliciousorder - file 20160324_15967f95b79b4ea0cc58b218fb37003e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ad5d5d49a56e23b41da4f704cd2f90e22526562831df1fc1d0706446b35bf0"

  strings:
    $s1  = "return WScript.CreateObject(QrxlO);" fullword ascii
    $s2  = "return mpuZpuy[0] + mpuZpuy[2] + mpuZpuy[4] + \".F\" + mpuZpuy[7] + mpuZpuy[9] + mpuZpuy[12] + mpuZpuy[14];" fullword ascii
    $s3  = "var be = true  , FwcE = ehA[7] + ehA[9] + ehA[11];" fullword ascii
    $s4  = "var mpuZpuy = EyFcd(xlgponLdsq+\" \"+\"System DO oEhak Obj GVgoHP ect jFGSrRu BeVrK\", \" \");" fullword ascii
    $s5  = "var ehA = (\"2.XMLHTTP fXyICVg KeZxc XML ream St sBtrIbmq AD SGDqGpt O aMnj D\").split(\" \");" fullword ascii
    $s6  = "sUWx.open(yEXKP,TrMLa,false);" fullword ascii
    $s7  = "function hvNs(MCuks) {" fullword ascii
    $s8  = "return uzRs[YQjbmW[0]];" fullword ascii
    $s9  = "return ANU.split(Dyfgr);" fullword ascii
    $s10 = "return ZMUbX;" fullword ascii
    $s11 = "rPC = r; break; " fullword ascii
    $s12 = "function FldE(XzidS,XQGjB) {" fullword ascii
    $s13 = "function EcxD(QrxlO) {" fullword ascii
    $s14 = "function xsrh(rKXAm) {" fullword ascii
    $s15 = "function MqWTD(Uuavat) {" fullword ascii
    $s16 = "function TzzU(cuGxV) {" fullword ascii
    $s17 = "function oAHgsnvGN(jFoipxQfVJI) {" fullword ascii
    $s18 = "function TLOZ(YeHNN,TrMLa,yEXKP) {" fullword ascii
    $s19 = "return IWO.size;" fullword ascii
    $s20 = "function xRymcxJ(voYi,ZkkUj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}