rule sig_20160311_55df037cdf6e1fb94eaa03c8f0cff846 {
  meta:
    description = "datamaliciousorder - file 20160311_55df037cdf6e1fb94eaa03c8f0cff846.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ae4414c2d45db986758e1dc5c18c581424281337b0e6938558c6130c5edddfa"

  strings:
    $s1  = "var wQ = true  , wcpj = ltZ[7] + ltZ[9] + ltZ[11];" fullword ascii
    $s2  = "return pHQQmaO[0] + pHQQmaO[2] + pHQQmaO[4] + \".F\" + pHQQmaO[7] + pHQQmaO[9] + pHQQmaO[12] + pHQQmaO[14];" fullword ascii
    $s3  = "var ltZ = (\"2.XMLHTTP KAgmEsp hccER XML ream St olBNqHpY AD OcRjtPC O vDey D\").split(\" \");" fullword ascii
    $s4  = "var pHQQmaO = \"Sc rLROoCr r QGrqWrzrV ipting bdBGVXD Kuq ile fbaFnKAQxlzxkT System uR ULAax Obj BEjSMP ect ViVGJsW\".split(\" " ascii
    $s5  = "function dlFi(UiEmY) {" fullword ascii
    $s6  = "return kFcmZv.position=555-555;" fullword ascii
    $s7  = "if (P >= EnRPW.length) {break;}" fullword ascii
    $s8  = "if (DhLFq > 135468-509){return true;} else {return false;}" fullword ascii
    $s9  = "xpV = Q; break; " fullword ascii
    $s10 = "return new ActiveXObject(XbEQwl);" fullword ascii
    $s11 = "return EMzUAuO" fullword ascii
    $s12 = "function OsqJkbe(PTZw,RFiLx) {" fullword ascii
    $s13 = "function QZxwc(XbEQwl) {" fullword ascii
    $s14 = "function zayvYnxG(BNiDy,TiawBL) {" fullword ascii
    $s15 = "return PTZw.ExpandEnvironmentStrings(RFiLx);" fullword ascii
    $s16 = "function lgce(GvpPF) {" fullword ascii
    $s17 = "return EBhcl;" fullword ascii
    $s18 = "function Soru(EnRPW) {" fullword ascii
    $s19 = "if(Q>=D.length) {break;}" fullword ascii
    $s20 = "function dvuZ(ycyRP,iKpbD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}