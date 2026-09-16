rule sig_20160308_3dca87e970008977ea283f2fd955cf5f {
  meta:
    description = "datamaliciousorder - file 20160308_3dca87e970008977ea283f2fd955cf5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fec1baeb13f30c87dc479af16e741dbccac39185426fae45f8056c798cb7672"

  strings:
    $s1  = "var xXdOnlP = \"Sc ffkOCVB r IQYkljxUl ipting zZNGbGD Qgz ile WCqeyecTmrBZKY System lQ bRivk Obj pGddRL ect AlUPRmU\".split(\" " ascii
    $s2  = "return xXdOnlP[0] + xXdOnlP[2] + xXdOnlP[4] + \".F\" + xXdOnlP[7] + xXdOnlP[9] + xXdOnlP[12] + xXdOnlP[14];" fullword ascii
    $s3  = "var hp = true  , dNVO = WlM[7] + WlM[9] + WlM[11];" fullword ascii
    $s4  = "var WlM = (\"2.XMLHTTP Xzfzscu ZczGy XML ream St uWbaBGPb AD zVVBOgg O XaGz D\").split(\" \");" fullword ascii
    $s5  = "VHVMS.open(xgUqd,XkPRV,false);" fullword ascii
    $s6  = "return qZGdxrE" fullword ascii
    $s7  = "function dplR(AKZpO) {" fullword ascii
    $s8  = "function PyXXpJHz(WFm) {" fullword ascii
    $s9  = "if (((new Date())>0,7871498888)) {" fullword ascii
    $s10 = "return KtTR.responseBody;" fullword ascii
    $s11 = "function aKOOlBsjW(aewLAZSZPcf) {" fullword ascii
    $s12 = "function fWaNwWD(KtTR) {" fullword ascii
    $s13 = "function xtraAmJQ() {" fullword ascii
    $s14 = "return WFm.size;" fullword ascii
    $s15 = "function nWyOf(VbNvUI) {" fullword ascii
    $s16 = "function WlTm(cIIBO) {" fullword ascii
    $s17 = "if (f >= cIIBO.length) {break;}" fullword ascii
    $s18 = "return zsjns.status;" fullword ascii
    $s19 = "function TLcD(VHVMS,XkPRV,xgUqd) {" fullword ascii
    $s20 = "function zZTQ(mwshl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}