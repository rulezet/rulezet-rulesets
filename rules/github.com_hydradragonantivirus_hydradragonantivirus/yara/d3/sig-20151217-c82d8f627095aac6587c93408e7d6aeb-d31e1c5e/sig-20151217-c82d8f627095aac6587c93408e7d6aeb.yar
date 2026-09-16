rule sig_20151217_c82d8f627095aac6587c93408e7d6aeb {
  meta:
    description = "datamaliciousorder - file 20151217_c82d8f627095aac6587c93408e7d6aeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79226cf1523fc91ce234fc96d1046aab2058491aeb412ed49436eee844a09284"

  strings:
    $s1  = "w(Math.cos(187), 2) - 1)));} gYnBmfvDC[ROdIUlEtBzv]++;}ROdIUlEtBzv++;} return wEyEzRZisSs}" fullword ascii
    $s2  = "function tyvuXEsLCERGOXUAp(CLiwv){wEyEzRZisSs= '';ROdIUlEtBzv=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s3  = "function tyvuXEsLCERGOXUAp(CLiwv){wEyEzRZisSs= '';ROdIUlEtBzv=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s4  = ") - 1));while(true){if (ROdIUlEtBzv >= (-510+546)/6){break;}gYnBmfvDC[ROdIUlEtBzv]=Math.round((Math.pow(Math.sin(852), 2) + Math" ascii
    $s5  = ".pow(Math.cos(852), 2) - 1)); while(true) { if(gYnBmfvDC[ROdIUlEtBzv] > CLiwv[ROdIUlEtBzv].length-(432+292)/724) { break; } if (" ascii
    $s6  = "function KEJBWko(iPUEgDxEjsVWecticxbGpBBMPjTJNXvuzZBU) {return !UGWtFXeLPCJ(pUZdsVPQlaPvoVM(iPUEgDxEjsVWecticxbGpBBMPjTJNXvuzZBU" ascii
    $s7  = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s8  = "function I(tSNSbMSWmGfq,MFTlgjnOsaLIyY){tSNSbMSWmGfq.push(MFTlgjnOsaLIyY);}" fullword ascii
    $s9  = "function wtugC(trkiuVYxXpO,UZIHkXWMkvUwP,WJUdeSVy){RAUy=zvDRBNopCWfYrHFSM(trkiuVYxXpO,UZIHkXWMkvUwP);hufpf=RAUy.toString(WJUdeSV" ascii
    $s10 = "function MvfosZsOJEDISjNWbnuPlfqNpOJHNPkWLnBbktFXGWxhNPaUYzSjOV(VaziJYVZHbkSp,sCUTiGhRwMtQYx){ return JyKMuLP[aDztLmmF[wtugC(Vaz" ascii
    $s11 = "function pUZdsVPQlaPvoVM(TvHHcQdRGHBeGKVStQA) {return parseFloat(TvHHcQdRGHBeGKVStQA);}" fullword ascii
    $s12 = "function vqNyslnGHrmvLBZ(LMvLKCoKcQZtQgMWf,iNUywyCmLAowOSikauWxSxtJxtptMkwHWS,hFZJAomnqRTVwAQdJrLSQbeiRUUhGehPzue){eval(LMvLKCoK" ascii
    $s13 = "function KEJBWko(iPUEgDxEjsVWecticxbGpBBMPjTJNXvuzZBU) {return !UGWtFXeLPCJ(pUZdsVPQlaPvoVM(iPUEgDxEjsVWecticxbGpBBMPjTJNXvuzZBU" ascii
    $s14 = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s15 = "function vqNyslnGHrmvLBZ(LMvLKCoKcQZtQgMWf,iNUywyCmLAowOSikauWxSxtJxtptMkwHWS,hFZJAomnqRTVwAQdJrLSQbeiRUUhGehPzue){eval(LMvLKCoK" ascii
    $s16 = "function wtugC(trkiuVYxXpO,UZIHkXWMkvUwP,WJUdeSVy){RAUy=zvDRBNopCWfYrHFSM(trkiuVYxXpO,UZIHkXWMkvUwP);hufpf=RAUy.toString(WJUdeSV" ascii
    $s17 = "function MvfosZsOJEDISjNWbnuPlfqNpOJHNPkWLnBbktFXGWxhNPaUYzSjOV(VaziJYVZHbkSp,sCUTiGhRwMtQYx){ return JyKMuLP[aDztLmmF[wtugC(Vaz" ascii
    $s18 = "function NYIDKaRrCzor(xKvYsBMQBgTLM) {return isFinite(xKvYsBMQBgTLM);}" fullword ascii
    $s19 = "function G(OQYmcIWpgIbyWv,hjpUwzrDIUTxd,LnwQlUBgMqB) {OQYmcIWpgIbyWv[hjpUwzrDIUTxd]=LnwQlUBgMqB;}" fullword ascii
    $s20 = "function zvDRBNopCWfYrHFSM(YDhYXtLwah,oGvJxIkzkb) {return parseInt(YDhYXtLwah,oGvJxIkzkb);}" fullword ascii

  condition:
    uint16(0) == 0x4461 and
    8 of them
}