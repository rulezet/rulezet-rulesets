rule sig_20160520_cf272fd26d37b0da721fb73b43bfd49e {
  meta:
    description = "datamaliciousorder - file 20160520_cf272fd26d37b0da721fb73b43bfd49e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84811a73a1437c870699dea14ee2a7a0ffdda63ceae778f1cf8a9822bd5e5717"

  strings:
    $s1  = "function XgtjQ(iEtNAQrz,zzjmY,FALoGuhoBx){iEtNAQrz.open();iEtNAQrz.type = 1;iEtNAQrz.write(zzjmY);iEtNAQrz.position = 0;iEtNAQrz" ascii
    $s2  = "function HKjJfxMr(haPoy) {var LQEpwOTt=bjTfBMJbLYfqhHFdpOUhk[2];for(var xhmUI=0;xhmUI<haPoy;xhmUI++){UnFuy+=LQEpwOTt.charAt(Math" ascii
    $s3  = "function XgtjQ(iEtNAQrz,zzjmY,FALoGuhoBx){iEtNAQrz.open();iEtNAQrz.type = 1;iEtNAQrz.write(zzjmY);iEtNAQrz.position = 0;iEtNAQrz" ascii
    $s4  = "function HKjJfxMr(haPoy) {var LQEpwOTt=bjTfBMJbLYfqhHFdpOUhk[2];for(var xhmUI=0;xhmUI<haPoy;xhmUI++){UnFuy+=LQEpwOTt.charAt(Math" ascii
    $s5  = "function yLqcEcp() {var pbeL=100000;var jtCUhM = 100;return Math.random()*(pbeL-jtCUhM)+jtCUhM;}" fullword ascii
    $s6  = "function mpNN(miqVRn,GbnuKIl){WZWX = bjTfBMJbLYfqhHFdpOUhk[11].split(bjTfBMJbLYfqhHFdpOUhk[12]);GbnuKIl.open(WZWX[0]+WZWX[2]+WZW" ascii
    $s7  = "X[3], miqVRn, false);GbnuKIl.send();}" fullword ascii
    $s8  = ".floor(Math.random()*LQEpwOTt.length));}return UnFuy;}" fullword ascii
    $s9  = "try{XVeeOVu=iTpBMuIxs(bDSVx[RJww], yLqcEcp() + bjTfBMJbLYfqhHFdpOUhk[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function cGIys(RNtcCQlL,zmxxUQ,dSyWBavuP){wqWHC=RNtcCQlL.split(dSyWBavuP);aqRuKNj = bjTfBMJbLYfqhHFdpOUhk[13];for(AzErxTqg=0;AzE" ascii
    $s11 = "function cGIys(RNtcCQlL,zmxxUQ,dSyWBavuP){wqWHC=RNtcCQlL.split(dSyWBavuP);aqRuKNj = bjTfBMJbLYfqhHFdpOUhk[13];for(AzErxTqg=0;AzE" ascii
    $s12 = "rxTqg<zmxxUQ.length;AzErxTqg++) {aqRuKNj+=wqWHC[zmxxUQ[AzErxTqg]];}return aqRuKNj.substring(3,aqRuKNj.length);}" fullword ascii
    $s13 = "function mpNN(miqVRn,GbnuKIl){WZWX = bjTfBMJbLYfqhHFdpOUhk[11].split(bjTfBMJbLYfqhHFdpOUhk[12]);GbnuKIl.open(WZWX[0]+WZWX[2]+WZW" ascii
    $s14 = "if (XVeeOVu==0) break;" fullword ascii
    $s15 = "function GYhTBW(GwSQuF){return GwSQuF.ExpandEnvironmentStrings(bjTfBMJbLYfqhHFdpOUhk[10])}" fullword ascii
    $s16 = "function egZOu(GwSQuF){return new ActiveXObject(GwSQuF);}" fullword ascii
    $s17 = "function iTpBMuIxs(CEZTREZyB,AoILEIv,bABkAAJY){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}