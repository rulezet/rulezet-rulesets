rule sig_20151217_847fce09951fedf149e014a658188bd8 {
  meta:
    description = "datamaliciousorder - file 20151217_847fce09951fedf149e014a658188bd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72a7a08818a90342d8576a8caed27cc510c5def2e0576f52a615247be7fe45a5"

  strings:
    $s1  = "function hmniuLNEDjzzuEONS(tuQZG){VJIZfJPecfl= '';oLEPPEcUaSQ=Math.round((Math.pow(Math.sin(537), 2) + Math.pow(Math.cos(537), 2" ascii
    $s2  = "pow(Math.cos(901), 2) - 1)));} rrHgbhYyy[oLEPPEcUaSQ]++;}oLEPPEcUaSQ++;} return VJIZfJPecfl}" fullword ascii
    $s3  = ") - 1));while(true){if (oLEPPEcUaSQ >= (2505+399)/484){break;}rrHgbhYyy[oLEPPEcUaSQ]=Math.round((Math.pow(Math.sin(858), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(858), 2) - 1)); while(true) { if(rrHgbhYyy[oLEPPEcUaSQ] > tuQZG[oLEPPEcUaSQ].length-(554+262)/816) { break; } if" ascii
    $s5  = "zTdpHmEWOHRduhsTepjlsFDMwqBwOboJMcu([tuQZG[oLEPPEcUaSQ][rrHgbhYyy[oLEPPEcUaSQ]]], Math.round((Math.pow(Math.sin(901), 2) + Math." ascii
    $s6  = "function hmniuLNEDjzzuEONS(tuQZG){VJIZfJPecfl= '';oLEPPEcUaSQ=Math.round((Math.pow(Math.sin(537), 2) + Math.pow(Math.cos(537), 2" ascii
    $s7  = "function lOQgrwn(vgVPGGfktTbJekoxOLLCxoMvSGuGEUaynjyf) {return !tQrKVGcenhU(wECNPBfTinlzZnK(vgVPGGfktTbJekoxOLLCxoMvSGuGEUaynjyf" ascii
    $s8  = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s9  = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s10 = "function IvrEN(UmzpkGifYUu,eFsIJcIWDevwJ,LizMHqYe){CgNG=JtQLZWLxasVpRVDYe(UmzpkGifYUu,eFsIJcIWDevwJ);esUjT=CgNG.toString(LizMHqY" ascii
    $s11 = "e);return esUjT;}" fullword ascii
    $s12 = "function IvrEN(UmzpkGifYUu,eFsIJcIWDevwJ,LizMHqYe){CgNG=JtQLZWLxasVpRVDYe(UmzpkGifYUu,eFsIJcIWDevwJ);esUjT=CgNG.toString(LizMHqY" ascii
    $s13 = "function c(SlaetgJfQTGMer,MngocPEEQQYZK,SLmcIYulEPe) {SlaetgJfQTGMer[MngocPEEQQYZK]=SLmcIYulEPe;}" fullword ascii
    $s14 = "function K(aMBRBPcXDwfN,KAZKNmPEOoPqBT){aMBRBPcXDwfN.push(KAZKNmPEOoPqBT);}" fullword ascii
    $s15 = "function CWhusCGWMvWJKUX(sUEWbpAJaQbmwrTxP,jvEDOFTvfpywMwbZgZbJSGPiCXQqmxCZhp,oxauMxmjZNwuEPLtuTYBQoAwclyKcSfdsCW){eval(sUEWbpAJ" ascii
    $s16 = "function JtQLZWLxasVpRVDYe(FcgoCbucOV,pIqRdHfnlK) {return parseInt(FcgoCbucOV,pIqRdHfnlK);}" fullword ascii
    $s17 = "function tMvaWvSzbPGdFQZLwDmzTdpHmEWOHRduhsTepjlsFDMwqBwOboJMcu(uBAztkXteyUJP,GyxnnlIylgvrwI){ return qOoGDGu[eqevNERS[IvrEN(uBA" ascii
    $s18 = "function lOQgrwn(vgVPGGfktTbJekoxOLLCxoMvSGuGEUaynjyf) {return !tQrKVGcenhU(wECNPBfTinlzZnK(vgVPGGfktTbJekoxOLLCxoMvSGuGEUaynjyf" ascii
    $s19 = "function tMvaWvSzbPGdFQZLwDmzTdpHmEWOHRduhsTepjlsFDMwqBwOboJMcu(uBAztkXteyUJP,GyxnnlIylgvrwI){ return qOoGDGu[eqevNERS[IvrEN(uBA" ascii
    $s20 = "function tQrKVGcenhU(hZXblFzdBGlEMb) {return isNaN(hZXblFzdBGlEMb);}" fullword ascii

  condition:
    uint16(0) == 0x7165 and
    8 of them
}