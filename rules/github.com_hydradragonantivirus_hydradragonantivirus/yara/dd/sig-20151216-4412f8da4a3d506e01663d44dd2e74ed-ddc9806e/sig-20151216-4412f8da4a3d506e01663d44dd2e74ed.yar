rule sig_20151216_4412f8da4a3d506e01663d44dd2e74ed {
  meta:
    description = "datamaliciousorder - file 20151216_4412f8da4a3d506e01663d44dd2e74ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc5fc1a07bb36a9bbd3eafe1ae05b9085afbf598e6b547d2f1d050616f73e90"

  strings:
    $s1  = "(Math.cos(86), 2) - 1)));} xCjYsdZpy[PCRacHIXsAK]++;}PCRacHIXsAK++;} return TsjHNmNwnHl}" fullword ascii
    $s2  = ") - 1));while(true){if (PCRacHIXsAK >= (3961+809)/795){break;}xCjYsdZpy[PCRacHIXsAK]=Math.round((Math.pow(Math.sin(616), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(616), 2) - 1)); while(true) { if(xCjYsdZpy[PCRacHIXsAK] > REAQi[PCRacHIXsAK].length-(-597+688)/91) { break; } if" ascii
    $s4  = "function owZdPlckXOkarQmoh(REAQi){TsjHNmNwnHl= '';PCRacHIXsAK=Math.round((Math.pow(Math.sin(125), 2) + Math.pow(Math.cos(125), 2" ascii
    $s5  = "function owZdPlckXOkarQmoh(REAQi){TsjHNmNwnHl= '';PCRacHIXsAK=Math.round((Math.pow(Math.sin(125), 2) + Math.pow(Math.cos(125), 2" ascii
    $s6  = "function CynSvdA(hrWTUWyAeuGyHhuXRVfSuhckEVoGNlHXzjNm) {return !PUcUxOxvFHy(EvWzuFRevUHlocx(hrWTUWyAeuGyHhuXRVfSuhckEVoGNlHXzjNm" ascii
    $s7  = "function PUcUxOxvFHy(NQVvOUasbuZWlB) {return isNaN(NQVvOUasbuZWlB);}" fullword ascii
    $s8  = "function w(lCQCFvugifuCDk,GHYRpqjejXswH,kRcnfKhGGAL) {lCQCFvugifuCDk[GHYRpqjejXswH]=kRcnfKhGGAL;}" fullword ascii
    $s9  = "function WkDbI(popBrVWwEUm,QKpImdFvBVRDs,cLvneWYc){JKjA=GnPxJavwaaVIulEqW(popBrVWwEUm,QKpImdFvBVRDs);QxpFQ=JKjA.toString(cLvneWY" ascii
    $s10 = "c);return QxpFQ;}" fullword ascii
    $s11 = "function GnPxJavwaaVIulEqW(NZMpoogIck,bXsRZuYVHs) {return parseInt(NZMpoogIck,bXsRZuYVHs);}" fullword ascii
    $s12 = "function WhRGhutrTCwhRCG(gEuzObiJNBtKucNMN,kNRgBsPLWuAbRUqrhUDVgTYlvOBuYDfuTV,KuKzxXRUquKLyXBZSWNghutaicPGBBwdVUj){eval(gEuzObiJ" ascii
    $s13 = "function wljcGrebmmlxqYQLIUOrrGuIPrgjidwgYWrOCeUfNxXnrVCJXDrPQr(lHEzkinTuXHgb,FziYxUfkYsiwXb){ return vYhrEBA[DSUTcSFo[WkDbI(lHE" ascii
    $s14 = "function WkDbI(popBrVWwEUm,QKpImdFvBVRDs,cLvneWYc){JKjA=GnPxJavwaaVIulEqW(popBrVWwEUm,QKpImdFvBVRDs);QxpFQ=JKjA.toString(cLvneWY" ascii
    $s15 = "function UAzHsJVgCtCV(ZDJtMUHPvrWVe) {return isFinite(ZDJtMUHPvrWVe);}" fullword ascii
    $s16 = "function wljcGrebmmlxqYQLIUOrrGuIPrgjidwgYWrOCeUfNxXnrVCJXDrPQr(lHEzkinTuXHgb,FziYxUfkYsiwXb){ return vYhrEBA[DSUTcSFo[WkDbI(lHE" ascii
    $s17 = "function WhRGhutrTCwhRCG(gEuzObiJNBtKucNMN,kNRgBsPLWuAbRUqrhUDVgTYlvOBuYDfuTV,KuKzxXRUquKLyXBZSWNghutaicPGBBwdVUj){eval(gEuzObiJ" ascii
    $s18 = "function l(QfMIPGWqQQWT,lCZYascHabvWff){QfMIPGWqQQWT.push(lCZYascHabvWff);}" fullword ascii
    $s19 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s20 = "function EvWzuFRevUHlocx(IfEUSjurpCRAcGnNOOz) {return parseFloat(IfEUSjurpCRAcGnNOOz);}" fullword ascii

  condition:
    uint16(0) == 0x5344 and
    8 of them
}