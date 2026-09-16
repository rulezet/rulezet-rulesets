rule sig_20160324_6d2780a00126b4a387d182bb79eb4d2c {
  meta:
    description = "datamaliciousorder - file 20160324_6d2780a00126b4a387d182bb79eb4d2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2abbea189f17e71c190a7ee5afb5d21d028348204b1b6606e5a60ad3cdf2e70c"

  strings:
    $s1  = "return WScript.CreateObject(GrjWS);" fullword ascii
    $s2  = "var Au = true  , vhRL = KIf[7] + KIf[9] + KIf[11];" fullword ascii
    $s3  = "return CEQwVwQ[0] + CEQwVwQ[2] + CEQwVwQ[4] + \".F\" + CEQwVwQ[7] + CEQwVwQ[9] + CEQwVwQ[12] + CEQwVwQ[14];" fullword ascii
    $s4  = "var KIf = (\"2.XMLHTTP HxxQTRr SvHlZ XML ream St wErYoGzK AD vzFNSeC O bIIT D\").split(\" \");" fullword ascii
    $s5  = "eEkN.open(SJCwl,XkZwN,false);" fullword ascii
    $s6  = "var CEQwVwQ = WZDSC(DMUrpfrOje+\" \"+\"System Aa uOZGt Obj zFEbWY ect yXQjiuj VrWlH\", \" \");" fullword ascii
    $s7  = "return qHK.split(bgCgm);" fullword ascii
    $s8  = "if (OXbAY > 196512-137){return true;} else {return false;}" fullword ascii
    $s9  = "function WqsP(GrjWS) {" fullword ascii
    $s10 = "return GtGE[BXZshO[0]];" fullword ascii
    $s11 = "function bjeV(Acvjo,XkZwN,SJCwl) {" fullword ascii
    $s12 = "return sfL.size;" fullword ascii
    $s13 = "function dMYFa(vxWbKN) {" fullword ascii
    $s14 = "function gqyIWLeG(LSix) {" fullword ascii
    $s15 = "return new ActiveXObject(kImv);" fullword ascii
    $s16 = "function ITQmO(uqxECf) {" fullword ascii
    $s17 = "function WZDSC(qHK,bgCgm) {" fullword ascii
    $s18 = "function cxFy(fzapP,bgfPX) {" fullword ascii
    $s19 = "return psQI.ExpandEnvironmentStrings(DBknS);" fullword ascii
    $s20 = "function oVBKbzb(psQI,DBknS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}