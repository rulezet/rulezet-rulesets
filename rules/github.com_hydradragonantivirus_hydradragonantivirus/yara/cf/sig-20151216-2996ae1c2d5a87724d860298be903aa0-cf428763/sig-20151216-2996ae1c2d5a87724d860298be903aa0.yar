rule sig_20151216_2996ae1c2d5a87724d860298be903aa0 {
  meta:
    description = "datamaliciousorder - file 20151216_2996ae1c2d5a87724d860298be903aa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62302857ec94f1c2fcc5933b689e8da6be46df2b81559fe327a8f4649ace1a76"

  strings:
    $s1  = ") - 1));while(true){if (ZMFeiOOSyJn >= (3395+871)/711){break;}GNjRWniOZ[ZMFeiOOSyJn]=Math.round((Math.pow(Math.sin(575), 2) + Ma" ascii
    $s2  = "function aLkLJMWdTBwWtAlhY(JkkqM){PWajjZWMSqj= '';ZMFeiOOSyJn=Math.round((Math.pow(Math.sin(992), 2) + Math.pow(Math.cos(992), 2" ascii
    $s3  = "th.pow(Math.cos(575), 2) - 1)); while(true) { if(GNjRWniOZ[ZMFeiOOSyJn] > JkkqM[ZMFeiOOSyJn].length-(488+81)/569) { break; } if " ascii
    $s4  = "w(Math.cos(908), 2) - 1)));} GNjRWniOZ[ZMFeiOOSyJn]++;}ZMFeiOOSyJn++;} return PWajjZWMSqj}" fullword ascii
    $s5  = "function aLkLJMWdTBwWtAlhY(JkkqM){PWajjZWMSqj= '';ZMFeiOOSyJn=Math.round((Math.pow(Math.sin(992), 2) + Math.pow(Math.cos(992), 2" ascii
    $s6  = "function bSHAUxC(yDwFlCcWcnconHlcyTPfnKlQMVbiRIdLDDkN) {return !wkgrUgrAwaF(fVirIqoWKsZGVGt(yDwFlCcWcnconHlcyTPfnKlQMVbiRIdLDDkN" ascii
    $s7  = "function NorVmbIabicIoGyHrVfcBCUCSyqgKfFoiCUDhpZeSLBXEPAvyvixpL(pthLAsOJCeODV,tjMbRKcqibUbXJ){ return VSmcOqU[hSJwEqEH[dZfPG(pth" ascii
    $s8  = "function fVirIqoWKsZGVGt(zdYiFuSiSeWaUOZdinN) {return parseFloat(zdYiFuSiSeWaUOZdinN);}" fullword ascii
    $s9  = "function dZfPG(VKpyZyaNeDE,okkZiqeyrJRPh,vSMJEQcX){mOwh=nArgBwoCYgXzFFbzN(VKpyZyaNeDE,okkZiqeyrJRPh);iYrSB=mOwh.toString(vSMJEQc" ascii
    $s10 = "function v(vnYVhMzvMzpyiM,xjZBLbzCJfwuU,IFOiDuzMnbk) {vnYVhMzvMzpyiM[xjZBLbzCJfwuU]=IFOiDuzMnbk;}" fullword ascii
    $s11 = "function NorVmbIabicIoGyHrVfcBCUCSyqgKfFoiCUDhpZeSLBXEPAvyvixpL(pthLAsOJCeODV,tjMbRKcqibUbXJ){ return VSmcOqU[hSJwEqEH[dZfPG(pth" ascii
    $s12 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s13 = "X);return iYrSB;}" fullword ascii
    $s14 = "function wkgrUgrAwaF(LbVliUupAaXagj) {return isNaN(LbVliUupAaXagj);}" fullword ascii
    $s15 = "function dZfPG(VKpyZyaNeDE,okkZiqeyrJRPh,vSMJEQcX){mOwh=nArgBwoCYgXzFFbzN(VKpyZyaNeDE,okkZiqeyrJRPh);iYrSB=mOwh.toString(vSMJEQc" ascii
    $s16 = "function nArgBwoCYgXzFFbzN(QhLIvlwHCc,VlqCwnFoab) {return parseInt(QhLIvlwHCc,VlqCwnFoab);}" fullword ascii
    $s17 = "function ceYqqvzqsGPD(KKemZypQhpNQf) {return isFinite(KKemZypQhpNQf);}" fullword ascii
    $s18 = "function bSHAUxC(yDwFlCcWcnconHlcyTPfnKlQMVbiRIdLDDkN) {return !wkgrUgrAwaF(fVirIqoWKsZGVGt(yDwFlCcWcnconHlcyTPfnKlQMVbiRIdLDDkN" ascii
    $s19 = "function GgQGeLzzzaSLDLq(xUdOPjuyRvBfUhbwu,eOJpsqRJRAWPljCegUfQkpLRLveawuZuSv,nfYCKxMbuaDOitCstQGwzmHdyUGMICIfqjf){eval(xUdOPjuy" ascii
    $s20 = "function GgQGeLzzzaSLDLq(xUdOPjuyRvBfUhbwu,eOJpsqRJRAWPljCegUfQkpLRLveawuZuSv,nfYCKxMbuaDOitCstQGwzmHdyUGMICIfqjf){eval(xUdOPjuy" ascii

  condition:
    uint16(0) == 0x5368 and
    8 of them
}