rule sig_20151210_972fa023665b091f5c83a87fcef75244 {
  meta:
    description = "datamaliciousorder - file 20151210_972fa023665b091f5c83a87fcef75244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f68f7480751147cedced37f142d130aa3674a2857578d14849d570978e9efadd"

  strings:
    $s1  = "function dItMfrC(FWbcpMPCSQXTOzGlNqZiRWFnOnXiEGwRoJjh) {return !isNaN(parseFloat(FWbcpMPCSQXTOzGlNqZiRWFnOnXiEGwRoJjh)) && isFin" ascii
    $s2  = "function dItMfrC(FWbcpMPCSQXTOzGlNqZiRWFnOnXiEGwRoJjh) {return !isNaN(parseFloat(FWbcpMPCSQXTOzGlNqZiRWFnOnXiEGwRoJjh)) && isFin" ascii
    $s3  = "utoxGli=(-807+807)/999;while(true){if(utoxGli>=(43067+581)/341){break;}DOoFjQYrDmmBm[utoxGli]=String.fromCharCode(utoxGli);utoxG" ascii
    $s4  = "function LpkHtsPXcvHKbEalM(XxDxg){RcGmQRiAVyr= '';for(pXzvxVVyEeb=(-566+566)/457; pXzvxVVyEeb < (1645+149)/897; pXzvxVVyEeb++) {" ascii
    $s5  = "function WdMoPHAQfwxOnLSEHqZjoqYKDZcLmPIlRWDIuancUUBDeIeKRGHarJ(vsnkaFJjQJwRE,JjAJriKABVIMou){ return DOoFjQYrDmmBm[xLOoX(vsnkaF" ascii
    $s6  = "function hmmFVHASoDc(VmYOOUfP,JopROY){return VmYOOUfP.split(JopROY)}" fullword ascii
    $s7  = "]++;}} return RcGmQRiAVyr}" fullword ascii
    $s8  = "function LpkHtsPXcvHKbEalM(XxDxg){RcGmQRiAVyr= '';for(pXzvxVVyEeb=(-566+566)/457; pXzvxVVyEeb < (1645+149)/897; pXzvxVVyEeb++) {" ascii
    $s9  = "AiPFGkUIi[pXzvxVVyEeb]=(-237+237)/883; while(true) { if(AiPFGkUIi[pXzvxVVyEeb] > XxDxg[pXzvxVVyEeb].length-(-578+785)/207) { bre" ascii
    $s10 = " nJzqC;}function SqTdWxBJrpnUtQj(RSGeFuZINfrBXVVVP){eval(RSGeFuZINfrBXVVVP)}" fullword ascii
    $s11 = "function WdMoPHAQfwxOnLSEHqZjoqYKDZcLmPIlRWDIuancUUBDeIeKRGHarJ(vsnkaFJjQJwRE,JjAJriKABVIMou){ return DOoFjQYrDmmBm[xLOoX(vsnkaF" ascii
    $s12 = "function xLOoX(xDDeAZNyckB,sOxSJgWBWxLkO,MDfbEkcv){oevT=parseInt(xDDeAZNyckB,sOxSJgWBWxLkO);nJzqC=oevT.toString(MDfbEkcv);return" ascii
    $s13 = "utoxGli=(-807+807)/999;while(true){if(utoxGli>=(43067+581)/341){break;}DOoFjQYrDmmBm[utoxGli]=String.fromCharCode(utoxGli);utoxG" ascii
    $s14 = "function xLOoX(xDDeAZNyckB,sOxSJgWBWxLkO,MDfbEkcv){oevT=parseInt(xDDeAZNyckB,sOxSJgWBWxLkO);nJzqC=oevT.toString(MDfbEkcv);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}