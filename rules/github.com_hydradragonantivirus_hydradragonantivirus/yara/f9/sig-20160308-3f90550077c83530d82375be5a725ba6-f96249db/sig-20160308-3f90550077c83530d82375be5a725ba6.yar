rule sig_20160308_3f90550077c83530d82375be5a725ba6 {
  meta:
    description = "datamaliciousorder - file 20160308_3f90550077c83530d82375be5a725ba6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3a6a55bc4a3dc67babd4019b83a70da637f009748bdc511420b6cd443512f33"

  strings:
    $s1  = "var sO = true  , YIgx = fpB[7] + fpB[9] + fpB[11];" fullword ascii
    $s2  = "return zVeDrbJ[0] + zVeDrbJ[2] + zVeDrbJ[4] + \".F\" + zVeDrbJ[7] + zVeDrbJ[9] + zVeDrbJ[12] + zVeDrbJ[14];" fullword ascii
    $s3  = "var zVeDrbJ = \"Sc YFlmXYG r rlQTOxVZe ipting VpLcMJO axo ile tQbeCBiXTEAAkN System wc HeOHS Obj GtDuVc ect mDanLyn\".split(\" " ascii
    $s4  = "NsDnW.open(ioCXy,jCWgG,false);" fullword ascii
    $s5  = "var fpB = (\"2.XMLHTTP NQZuVjt LdaZK XML ream St fdGhXrLw AD QrINwCw O ztFF D\").split(\" \");" fullword ascii
    $s6  = "function qHsF(YdYKy,brGiw) {" fullword ascii
    $s7  = "function YiSDegL(UWAd) {" fullword ascii
    $s8  = "if (U >= jmGnb.length) {break;}" fullword ascii
    $s9  = "return VS.ExpandEnvironmentStrings(SXnbH[6]+SXnbH[7]+SXnbH[8]);" fullword ascii
    $s10 = "function SyJvrXfBG(CMoyqDKBwHz) {" fullword ascii
    $s11 = "function YVoE(NsDnW,jCWgG,ioCXy) {" fullword ascii
    $s12 = "function oWjtOAwj() {" fullword ascii
    $s13 = "return VJLq.responseBody;" fullword ascii
    $s14 = "function Euja(XsInp) {" fullword ascii
    $s15 = "return ekBtU;" fullword ascii
    $s16 = "function xDYU(jmGnb) {" fullword ascii
    $s17 = "function ORrL(GWEFo,NfWQc) {" fullword ascii
    $s18 = "function GzBz(SiOCt) {" fullword ascii
    $s19 = "return new ActiveXObject(MrEEmp);" fullword ascii
    $s20 = "if (ccKml == 1111-911){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}