rule sig_20151217_4f958d7f34782eae8c9a894c9061b9d8 {
  meta:
    description = "datamaliciousorder - file 20151217_4f958d7f34782eae8c9a894c9061b9d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d278e6b698aad95ae72232219718f4ab37d651f5094561b4e3d67437e4cb85a1"

  strings:
    $s1  = ".pow(Math.cos(54), 2) - 1)); while(true) { if(xHzUiQyOM[VzLetJkrAWD] > KRWjz[VzLetJkrAWD].length-(-56+389)/333) { break; } if (g" ascii
    $s2  = "(Math.cos(928), 2) - 1)));} xHzUiQyOM[VzLetJkrAWD]++;}VzLetJkrAWD++;} return VEZzoXBIbYf}" fullword ascii
    $s3  = "function rmeyJrXnfaiKjjUPB(KRWjz){VEZzoXBIbYf= '';VzLetJkrAWD=Math.round((Math.pow(Math.sin(111), 2) + Math.pow(Math.cos(111), 2" ascii
    $s4  = ") - 1));while(true){if (VzLetJkrAWD >= (411+867)/213){break;}xHzUiQyOM[VzLetJkrAWD]=Math.round((Math.pow(Math.sin(54), 2) + Math" ascii
    $s5  = "function rmeyJrXnfaiKjjUPB(KRWjz){VEZzoXBIbYf= '';VzLetJkrAWD=Math.round((Math.pow(Math.sin(111), 2) + Math.pow(Math.cos(111), 2" ascii
    $s6  = "function gKpDSOw(adaSaPagbvThjfxGGsdHlMmsVBdYakGEOaNQ) {return !xxFExJPbZJN(biNyhwgTmYsbynP(adaSaPagbvThjfxGGsdHlMmsVBdYakGEOaNQ" ascii
    $s7  = "function gKpDSOw(adaSaPagbvThjfxGGsdHlMmsVBdYakGEOaNQ) {return !xxFExJPbZJN(biNyhwgTmYsbynP(adaSaPagbvThjfxGGsdHlMmsVBdYakGEOaNQ" ascii
    $s8  = "function biNyhwgTmYsbynP(SehNLpTTUbiGQcogpSY) {return parseFloat(SehNLpTTUbiGQcogpSY);}" fullword ascii
    $s9  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s10 = "function HUJQYMwyWWzjYVvQZ(yxwHMZzanR,sPrRhSCuBf) {return parseInt(yxwHMZzanR,sPrRhSCuBf);}" fullword ascii
    $s11 = "function lgHaospGFYbSgKTlgmOpdcoQsWxkOpWftvExMfDJIBFfrUeawyaDlv(jDpTVEmUxmWyt,XTFeBxaHTqJJjf){ return VQgwaoK[JzRnCviE[JyaNx(jDp" ascii
    $s12 = "function ytwreZVgzVkjFeB(FoboFBdRILQVYTFlw,KFXhIXKEiHTwqFDyECHEKWGcsHvOniPrdc,XQltcNuJqdtsTJQKWTuDEiaRZPLfoQqbocL){eval(FoboFBdR" ascii
    $s13 = "function xxFExJPbZJN(zpeLhpckVBXIHV) {return isNaN(zpeLhpckVBXIHV);}" fullword ascii
    $s14 = "function nvXUVpxZKpUz(sQytxODPrxVtF) {return isFinite(sQytxODPrxVtF);}" fullword ascii
    $s15 = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s16 = "function j(uQHzxczaaGnvWH,IXSzbkazcoCpW,YLZunzHHqoI) {uQHzxczaaGnvWH[IXSzbkazcoCpW]=YLZunzHHqoI;}" fullword ascii
    $s17 = "function JyaNx(ydIilGnsEjA,bGNeJURGnOeqU,FaTlBznD){FNwk=HUJQYMwyWWzjYVvQZ(ydIilGnsEjA,bGNeJURGnOeqU);BuQnp=FNwk.toString(FaTlBzn" ascii
    $s18 = "function ytwreZVgzVkjFeB(FoboFBdRILQVYTFlw,KFXhIXKEiHTwqFDyECHEKWGcsHvOniPrdc,XQltcNuJqdtsTJQKWTuDEiaRZPLfoQqbocL){eval(FoboFBdR" ascii
    $s19 = "D);return BuQnp;}" fullword ascii
    $s20 = "function JyaNx(ydIilGnsEjA,bGNeJURGnOeqU,FaTlBznD){FNwk=HUJQYMwyWWzjYVvQZ(ydIilGnsEjA,bGNeJURGnOeqU);BuQnp=FNwk.toString(FaTlBzn" ascii

  condition:
    uint16(0) == 0x7a4a and
    8 of them
}