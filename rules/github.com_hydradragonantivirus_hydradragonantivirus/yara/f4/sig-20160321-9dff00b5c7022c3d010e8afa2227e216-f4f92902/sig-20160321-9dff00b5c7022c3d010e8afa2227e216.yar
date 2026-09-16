rule sig_20160321_9dff00b5c7022c3d010e8afa2227e216 {
  meta:
    description = "datamaliciousorder - file 20160321_9dff00b5c7022c3d010e8afa2227e216.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfcfbb2d37cfc9a5f2a8324db5b0ecd8b1681c26f5f8a7ae88b1cb029afdb305"

  strings:
    $s1  = "return WScript.CreateObject(QpJsq);" fullword ascii
    $s2  = "function YspyOIs(wDXn,bcvoC) {" fullword ascii
    $s3  = "return YspyOIs(UX,CwCDZ[904-898]+CwCDZ[833-826]+CwCDZ[483-475]);" fullword ascii
    $s4  = "var Lg = true  , KRvp = zhO[7] + zhO[9] + zhO[11];" fullword ascii
    $s5  = "return ybDjKVK[0] + ybDjKVK[2] + ybDjKVK[4] + \".F\" + ybDjKVK[7] + ybDjKVK[9] + ybDjKVK[12] + ybDjKVK[14];" fullword ascii
    $s6  = "var ybDjKVK = PxYLR(FognrKnDNw+\" \"+\"System uH XgKgC Obj pkleUb ect lMGUXQI yBhNx\", \" \");" fullword ascii
    $s7  = "tyvwa.open(mHKAn,muEPW,false);" fullword ascii
    $s8  = "var zhO = (\"2.XMLHTTP OnbvTeJ vsEdN XML ream St WrJpXRTn AD MOwjpIo O kdhv D\").split(\" \");" fullword ascii
    $s9  = "function gdvO(pYKiE) {" fullword ascii
    $s10 = "function PdSq(iechX) {" fullword ascii
    $s11 = "function ZsAR(iJGRl) {" fullword ascii
    $s12 = "if (sxeCs == 512-312){return true;} else {return false;}" fullword ascii
    $s13 = "function ppDE(QpJsq) {" fullword ascii
    $s14 = "return Qeqq[yIqsJM[0]];" fullword ascii
    $s15 = "function Aism(jbnym) {" fullword ascii
    $s16 = "if (pYKiE > 151493-744){return true;} else {return false;}" fullword ascii
    $s17 = "function buKNrADAY(olsbw) {" fullword ascii
    $s18 = "function oqDfaSU(Qeqq) {" fullword ascii
    $s19 = "function tSmT(aYmUh) {" fullword ascii
    $s20 = "return Tzi.split(lImMq);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}