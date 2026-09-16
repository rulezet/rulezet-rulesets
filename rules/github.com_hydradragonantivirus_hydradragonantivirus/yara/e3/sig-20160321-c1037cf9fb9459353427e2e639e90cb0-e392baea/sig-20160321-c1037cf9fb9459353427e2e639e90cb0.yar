rule sig_20160321_c1037cf9fb9459353427e2e639e90cb0 {
  meta:
    description = "datamaliciousorder - file 20160321_c1037cf9fb9459353427e2e639e90cb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "485a584a17ae01af0a995579fa5d29156c1a8dd0df12e1b9105967e8eddc8b97"

  strings:
    $s1  = "return WScript.CreateObject(iQxXi);" fullword ascii
    $s2  = "return xSgnliN[0] + xSgnliN[2] + xSgnliN[4] + \".F\" + xSgnliN[7] + xSgnliN[9] + xSgnliN[12] + xSgnliN[14];" fullword ascii
    $s3  = "var uv = true  , DrgR = RPB[7] + RPB[9] + RPB[11];" fullword ascii
    $s4  = "QQT.CreateFolder(Byon);" fullword ascii
    $s5  = "var xSgnliN = erAZH(wlnTKNQZzn+\" \"+\"System SC bgpJl Obj PblxKD ect ZARcNak rKZCi\", \" \");" fullword ascii
    $s6  = "dbKAu.open(JbiBa,Twltf,false);" fullword ascii
    $s7  = "var RPB = (\"2.XMLHTTP duQjEuH YQYAs XML ream St ISDfmGPR AD VpnwMHm O NXvN D\").split(\" \");" fullword ascii
    $s8  = "if (E >= DhkZk.length) {break;}" fullword ascii
    $s9  = "function FvUQztR(gDyh,uhQgu) {" fullword ascii
    $s10 = "function Vktk(PNTot) {" fullword ascii
    $s11 = "return Ibpku.status;" fullword ascii
    $s12 = "function VRVP(tqRHD) {" fullword ascii
    $s13 = "function vnCsaVde(HtR) {" fullword ascii
    $s14 = "return FHto[QlrkTd[0]];" fullword ascii
    $s15 = "function eKWiDnp(FHto) {" fullword ascii
    $s16 = "return FvUQztR(Ew,wrCyF[736-730]+wrCyF[509-502]+wrCyF[235-227]);" fullword ascii
    $s17 = "function ZQzL(Ibpku) {" fullword ascii
    $s18 = "return SaB.split(pKVSj);" fullword ascii
    $s19 = "mdo = r; break; " fullword ascii
    $s20 = "function mAPc(dbKAu,Twltf,JbiBa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}