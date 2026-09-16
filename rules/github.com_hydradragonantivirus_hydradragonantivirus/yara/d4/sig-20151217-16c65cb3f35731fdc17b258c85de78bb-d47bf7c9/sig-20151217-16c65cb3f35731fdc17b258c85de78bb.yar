rule sig_20151217_16c65cb3f35731fdc17b258c85de78bb {
  meta:
    description = "datamaliciousorder - file 20151217_16c65cb3f35731fdc17b258c85de78bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01c096b4351665195bfa0914b366a35d7d05ffa2ce3a6a23664ab327a0ddcbc6"

  strings:
    $s1  = "Math.cos(600), 2) - 1)));} SmXVmpVSP[fjzNXewaeyl]++;}fjzNXewaeyl++;} return CNIXriViDOl}" fullword ascii
    $s2  = "h.pow(Math.cos(942), 2) - 1)); while(true) { if(SmXVmpVSP[fjzNXewaeyl] > nmUXP[fjzNXewaeyl].length-(677+242)/919) { break; } if " ascii
    $s3  = "function DMKgXqzvieYrJyJFN(nmUXP){CNIXriViDOl= '';fjzNXewaeyl=Math.round((Math.pow(Math.sin(174), 2) + Math.pow(Math.cos(174), 2" ascii
    $s4  = ") - 1));while(true){if (fjzNXewaeyl >= (499+413)/152){break;}SmXVmpVSP[fjzNXewaeyl]=Math.round((Math.pow(Math.sin(942), 2) + Mat" ascii
    $s5  = "function DMKgXqzvieYrJyJFN(nmUXP){CNIXriViDOl= '';fjzNXewaeyl=Math.round((Math.pow(Math.sin(174), 2) + Math.pow(Math.cos(174), 2" ascii
    $s6  = "function bDjlOJG(JxvYWknCBYfpzUMeHmSKxahwAeoxlbEbKgcl) {return !hyKSTeAwiHC(wNkYBevoCCRbyYc(JxvYWknCBYfpzUMeHmSKxahwAeoxlbEbKgcl" ascii
    $s7  = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s8  = "function I(TQqFYSUHHWCMof,sgMVPWqPtTnRx,LiYLszHLXnc) {TQqFYSUHHWCMof[sgMVPWqPtTnRx]=LiYLszHLXnc;}" fullword ascii
    $s9  = "function tcMvJztwifRU(HOFZCPJWrLXbB) {return isFinite(HOFZCPJWrLXbB);}" fullword ascii
    $s10 = "i);return QvPRW;}" fullword ascii
    $s11 = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s12 = "function gDILiIxsBDFDMPy(ilyrmWuRWBchgHwMC,IiugIxwfixlJUoNXTxGxVfaIgPbIZmGMwQ,MAwPzVgmcHoNbJilncXiaGAEhiWANQFNGBo){eval(ilyrmWuR" ascii
    $s13 = "function gDILiIxsBDFDMPy(ilyrmWuRWBchgHwMC,IiugIxwfixlJUoNXTxGxVfaIgPbIZmGMwQ,MAwPzVgmcHoNbJilncXiaGAEhiWANQFNGBo){eval(ilyrmWuR" ascii
    $s14 = "function iCweJ(ZawwqcrzAfw,amroFXGYJtKyT,izDPsVIi){WYpL=ILRiTRhbqbAUJJweN(ZawwqcrzAfw,amroFXGYJtKyT);QvPRW=WYpL.toString(izDPsVI" ascii
    $s15 = "function T(ivGxKSQHyYlL,hMrsUDVjTPGiiI){ivGxKSQHyYlL.push(hMrsUDVjTPGiiI);}" fullword ascii
    $s16 = "function QEiYRBbgQCSBlVdDRFJmXgZXOzEZkInNSPULHUpdpqYDhcGxyrJSEQ(BRnIoRllwLAME,xjIwEeezcXfyoE){ return LrfLpKr[hMrNmUaj[iCweJ(BRn" ascii
    $s17 = "function ILRiTRhbqbAUJJweN(xUKkfZkBrs,DkdlbyLtCy) {return parseInt(xUKkfZkBrs,DkdlbyLtCy);}" fullword ascii
    $s18 = "function hyKSTeAwiHC(bHfjrdGLNNumNu) {return isNaN(bHfjrdGLNNumNu);}" fullword ascii
    $s19 = "function bDjlOJG(JxvYWknCBYfpzUMeHmSKxahwAeoxlbEbKgcl) {return !hyKSTeAwiHC(wNkYBevoCCRbyYc(JxvYWknCBYfpzUMeHmSKxahwAeoxlbEbKgcl" ascii
    $s20 = "function iCweJ(ZawwqcrzAfw,amroFXGYJtKyT,izDPsVIi){WYpL=ILRiTRhbqbAUJJweN(ZawwqcrzAfw,amroFXGYJtKyT);QvPRW=WYpL.toString(izDPsVI" ascii

  condition:
    uint16(0) == 0x4d68 and
    8 of them
}