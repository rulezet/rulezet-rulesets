rule sig_20160314_eb3929df0793e26e8d08e07a1409da62 {
  meta:
    description = "datamaliciousorder - file 20160314_eb3929df0793e26e8d08e07a1409da62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24e96a485330b264f40fad6b18ea5eac2668ee35998f7b359c92c58e2ea0877"

  strings:
    $s1  = "return QBoLaKl[0] + QBoLaKl[2] + QBoLaKl[4] + \".F\" + QBoLaKl[7] + QBoLaKl[9] + QBoLaKl[12] + QBoLaKl[14];" fullword ascii
    $s2  = "var av = true  , hXwf = erL[7] + erL[9] + erL[11];" fullword ascii
    $s3  = "var QBoLaKl = \"Sc SLjsKhu r wXPrkIgMh ipting WAwYutZ YMt ile NUMDLDdnWSScDl System TT UuWFS Obj zvNAYG ect rkYUbNn aItmS\".spli" ascii
    $s4  = "var QBoLaKl = \"Sc SLjsKhu r wXPrkIgMh ipting WAwYutZ YMt ile NUMDLDdnWSScDl System TT UuWFS Obj zvNAYG ect rkYUbNn aItmS\".spli" ascii
    $s5  = "FeLPC.open(EBjFd,gbEoY,false);" fullword ascii
    $s6  = "var erL = (\"2.XMLHTTP OQIZQYS bTXpV XML ream St qbEijURx AD RMUejRG O vaHP D\").split(\" \");" fullword ascii
    $s7  = "function TmHYADBeQ() {" fullword ascii
    $s8  = "function FxNnbhy(fJPC) {" fullword ascii
    $s9  = "function nKfKRkS(TMxC,vxDRS) {" fullword ascii
    $s10 = "return TMxC.ExpandEnvironmentStrings(vxDRS);" fullword ascii
    $s11 = "return wfsyZUk" fullword ascii
    $s12 = "function lXupJ(kCSmCu) {" fullword ascii
    $s13 = "return EbpOc;" fullword ascii
    $s14 = "function dTJd(BGtta) {" fullword ascii
    $s15 = "function fhQj(esetl) {" fullword ascii
    $s16 = "function Gxjaazpy() {" fullword ascii
    $s17 = "if (o >= bqOCQ.length) {break;}" fullword ascii
    $s18 = "function ePChG(gglGWc) {" fullword ascii
    $s19 = "unv = P; break; " fullword ascii
    $s20 = "return gglGWc.position=813-813;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}