rule sig_20160308_e52226679c587e9d223a173451b05094 {
  meta:
    description = "datamaliciousorder - file 20160308_e52226679c587e9d223a173451b05094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d75a543c7ea2cd193bb91164e494441ee7fe5d3e025c72ab0f75ba9b2dbbcd9"

  strings:
    $s1  = "return QgUsDic[0] + QgUsDic[2] + QgUsDic[4] + \".F\" + QgUsDic[7] + QgUsDic[9] + QgUsDic[12] + QgUsDic[14];" fullword ascii
    $s2  = "var ps = true  , gguu = yLV[7] + yLV[9] + yLV[11];" fullword ascii
    $s3  = "AEFOc.open(JDylF,bJsLV,false);" fullword ascii
    $s4  = "var QgUsDic = \"Sc MKXwGSk r WktzHRLrc ipting CMLRHdJ yCF ile FxCuWaxYUuzBKh System PJ MTRAn Obj fLukcj ect yGuZvlX\".split(\" " ascii
    $s5  = "var yLV = (\"2.XMLHTTP MfBfioK ytINs XML ream St cnPnFShP AD ZBrIGZH O uIdp D\").split(\" \");" fullword ascii
    $s6  = "function lFYG(hyAWv,VGqPe) {" fullword ascii
    $s7  = "NLX = Y; break; " fullword ascii
    $s8  = "return jC.ExpandEnvironmentStrings(aWAux[6]+aWAux[7]+aWAux[8]);" fullword ascii
    $s9  = "function soZC(PWOyb) {" fullword ascii
    $s10 = "return mkhBd.status;" fullword ascii
    $s11 = "if (bVixf == 346-146){return true;} else {return false;}" fullword ascii
    $s12 = "function hgEpvmU(oxjV) {" fullword ascii
    $s13 = "function lZEX(qwjav) {" fullword ascii
    $s14 = "return ddX.size;" fullword ascii
    $s15 = "return new ActiveXObject(HPLeiX);" fullword ascii
    $s16 = "function wZQDlbjUT(joewEBOCVEv) {" fullword ascii
    $s17 = "if (qwjav > 170989-513){return true;} else {return false;}" fullword ascii
    $s18 = "function rTZs(AEFOc,bJsLV,JDylF) {" fullword ascii
    $s19 = "function YhBpMdGW() {" fullword ascii
    $s20 = "function mxSj(MnuHt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}