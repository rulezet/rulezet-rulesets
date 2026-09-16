rule sig_20160321_06de05770935071f7095f79f193d1c49 {
  meta:
    description = "datamaliciousorder - file 20160321_06de05770935071f7095f79f193d1c49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3da11beba018ff8e7389f7ef191b0f0000ae99534ac4c95448fbf7e2c6d764ac"

  strings:
    $s1  = "return WScript.CreateObject(rHWNR);" fullword ascii
    $s2  = "return qbIDthM[0] + qbIDthM[2] + qbIDthM[4] + \".F\" + qbIDthM[7] + qbIDthM[9] + qbIDthM[12] + qbIDthM[14];" fullword ascii
    $s3  = "var fF = true  , UtoJ = zUo[7] + zUo[9] + zUo[11];" fullword ascii
    $s4  = "dJfpm.open(kgqdV,QqpZt,false);" fullword ascii
    $s5  = "var qbIDthM = nsJOk(iSPHkmGXje+\" \"+\"System Ov DTfMP Obj JPQheO ect ZuNpmWY UnpTw\", \" \");" fullword ascii
    $s6  = "var zUo = (\"2.XMLHTTP dKSTaIi doFlR XML ream St zcRkgoOL AD eAXvroR O UgUS D\").split(\" \");" fullword ascii
    $s7  = "function uryP(xPtuV) {" fullword ascii
    $s8  = "return maStB;" fullword ascii
    $s9  = "return Odb.split(oIhif);" fullword ascii
    $s10 = "function eMdB(yBCND,BLBOg) {" fullword ascii
    $s11 = "return new ActiveXObject(dAFjWB);" fullword ascii
    $s12 = "return ksg.size;" fullword ascii
    $s13 = "if (JOKWX > 184270-786){return true;} else {return false;}" fullword ascii
    $s14 = "function IAZI(hdlwi) {" fullword ascii
    $s15 = "return NxsL[ZGlZFY[0]];" fullword ascii
    $s16 = "return CCZwRF.position=575-575;" fullword ascii
    $s17 = "function IEnr(rHWNR) {" fullword ascii
    $s18 = "if(m>=L.length) {break;}" fullword ascii
    $s19 = "function TqSl(PdUXu,hwVKu) {" fullword ascii
    $s20 = "function FuBn(dJfpm,QqpZt,kgqdV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}