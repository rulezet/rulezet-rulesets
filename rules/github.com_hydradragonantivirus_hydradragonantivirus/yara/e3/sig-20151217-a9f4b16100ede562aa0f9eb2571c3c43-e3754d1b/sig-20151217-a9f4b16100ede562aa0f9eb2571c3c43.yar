rule sig_20151217_a9f4b16100ede562aa0f9eb2571c3c43 {
  meta:
    description = "datamaliciousorder - file 20151217_a9f4b16100ede562aa0f9eb2571c3c43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "041f919bdbd6675054a38b8de87526e6bea7c1c079804904ac2e4600d23bf3fa"

  strings:
    $s1  = "function wLGqwQeuTnUkBrrWo(atDZO){UifMmvuUDvg= '';OGXVDVtlWUl=Math.round((Math.pow(Math.sin(813), 2) + Math.pow(Math.cos(813), 2" ascii
    $s2  = "ow(Math.cos(824), 2) - 1)));} rckTwBLtu[OGXVDVtlWUl]++;}OGXVDVtlWUl++;} return UifMmvuUDvg}" fullword ascii
    $s3  = ") - 1));while(true){if (OGXVDVtlWUl >= (2680+260)/490){break;}rckTwBLtu[OGXVDVtlWUl]=Math.round((Math.pow(Math.sin(574), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(574), 2) - 1)); while(true) { if(rckTwBLtu[OGXVDVtlWUl] > atDZO[OGXVDVtlWUl].length-(480+10)/490) { break; } if " ascii
    $s5  = "function wLGqwQeuTnUkBrrWo(atDZO){UifMmvuUDvg= '';OGXVDVtlWUl=Math.round((Math.pow(Math.sin(813), 2) + Math.pow(Math.cos(813), 2" ascii
    $s6  = "function cIRjUxl(xuUtCFOdqaqSGPLgooxhSxaUykerZwnNKwBr) {return !ZqaYvwNTfec(nUczXGCCGBLWNrA(xuUtCFOdqaqSGPLgooxhSxaUykerZwnNKwBr" ascii
    $s7  = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s8  = "function JYMHsYfWFKwiVDAyTCEIZBoCiuiwDKyftIiOsoDtTuVPtrYltKXZhJ(rdHSLBvvunkmH,EYFnHBAWkhuzAa){ return Jxaotlv[uxPjbSwy[chSwM(rdH" ascii
    $s9  = "function ZqaYvwNTfec(DeYBwZUyLKBHHh) {return isNaN(DeYBwZUyLKBHHh);}" fullword ascii
    $s10 = "function nUczXGCCGBLWNrA(GhSWZfYBdjiZVdwOJBA) {return parseFloat(GhSWZfYBdjiZVdwOJBA);}" fullword ascii
    $s11 = "function JYMHsYfWFKwiVDAyTCEIZBoCiuiwDKyftIiOsoDtTuVPtrYltKXZhJ(rdHSLBvvunkmH,EYFnHBAWkhuzAa){ return Jxaotlv[uxPjbSwy[chSwM(rdH" ascii
    $s12 = "l);return BeNKx;}" fullword ascii
    $s13 = "function cIRjUxl(xuUtCFOdqaqSGPLgooxhSxaUykerZwnNKwBr) {return !ZqaYvwNTfec(nUczXGCCGBLWNrA(xuUtCFOdqaqSGPLgooxhSxaUykerZwnNKwBr" ascii
    $s14 = "function fMwAPdqWplCHgroHA(flsZMyJEby,ODquGmfGsV) {return parseInt(flsZMyJEby,ODquGmfGsV);}" fullword ascii
    $s15 = "function VVXWiMmaOVkIUuB(JhLVueaxxnfuJGLgr,MapiuHjWdxtofthFXiZsbkbKrcnUrTBXEL,xjuKSwkLbSQZTeMQxsyZaQaqWMWgeODfWIr){eval(JhLVueax" ascii
    $s16 = ",'-','.','V','?','n','%','K','W','y','R','X','*','`','9','d','Q','U','D','Y','`',')','Z','d','*',':','+','z','[','.','s',String." ascii
    $s17 = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s18 = "function dSVaUHJKDXyv(XMCheazijNGVV) {return isFinite(XMCheazijNGVV);}" fullword ascii
    $s19 = "function y(kRlLalfSPVGhaE,qucBURBFJJuVE,fMTaYpHWfQK) {kRlLalfSPVGhaE[qucBURBFJJuVE]=fMTaYpHWfQK;}" fullword ascii
    $s20 = "function VVXWiMmaOVkIUuB(JhLVueaxxnfuJGLgr,MapiuHjWdxtofthFXiZsbkbKrcnUrTBXEL,xjuKSwkLbSQZTeMQxsyZaQaqWMWgeODfWIr){eval(JhLVueax" ascii

  condition:
    uint16(0) == 0x7875 and
    8 of them
}