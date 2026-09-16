rule sig_20160520_dccd907cd13315b7cda945ab423578f5 {
  meta:
    description = "datamaliciousorder - file 20160520_dccd907cd13315b7cda945ab423578f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c395a4879bbefda68ba2becf68351f75e1925677f544a546c18bfb1d1523f07c"

  strings:
    $s1  = "function CdBVYmGw(NdTzv) {var IBUSEoaF=FZGGUNovYjncnamwWWOxNDGq[2];for(var YsJEu=0;YsJEu<NdTzv;YsJEu++){zmoXT+=IBUSEoaF.charAt(M" ascii
    $s2  = "function CdBVYmGw(NdTzv) {var IBUSEoaF=FZGGUNovYjncnamwWWOxNDGq[2];for(var YsJEu=0;YsJEu<NdTzv;YsJEu++){zmoXT+=IBUSEoaF.charAt(M" ascii
    $s3  = "ath.floor(Math.random()*IBUSEoaF.length));}return zmoXT;}" fullword ascii
    $s4  = "function jPcs(LfRbVL,pgMnkaH){QMzG = FZGGUNovYjncnamwWWOxNDGq[11].split(FZGGUNovYjncnamwWWOxNDGq[12]);pgMnkaH.open(QMzG[0]+QMzG[" ascii
    $s5  = "function EXHMa(yGnPPWUo,uJSrnz,SoRvfXeds){tiPJy=yGnPPWUo.split(SoRvfXeds);SobaDYy = FZGGUNovYjncnamwWWOxNDGq[13];for(LzBPvbvi=0;" ascii
    $s6  = "if (fRWDVXv==0) break;" fullword ascii
    $s7  = "function sJTMx(uTcunBtK,teDqs,mYKnlvRLNn){uTcunBtK.open();uTcunBtK.type = 1;uTcunBtK.write(teDqs);uTcunBtK.position = 0;uTcunBtK" ascii
    $s8  = "function sJTMx(uTcunBtK,teDqs,mYKnlvRLNn){uTcunBtK.open();uTcunBtK.type = 1;uTcunBtK.write(teDqs);uTcunBtK.position = 0;uTcunBtK" ascii
    $s9  = "function EJGaIqe() {var FBwQ=100000;var zDAXUD = 100;return Math.random()*(FBwQ-zDAXUD)+zDAXUD;}" fullword ascii
    $s10 = "LzBPvbvi<uJSrnz.length;LzBPvbvi++) {SobaDYy+=tiPJy[uJSrnz[LzBPvbvi]];}return SobaDYy.substring(3,SobaDYy.length);}" fullword ascii
    $s11 = "function rXGMg(GqpaTg){return new ActiveXObject(GqpaTg);}" fullword ascii
    $s12 = "function jPcs(LfRbVL,pgMnkaH){QMzG = FZGGUNovYjncnamwWWOxNDGq[11].split(FZGGUNovYjncnamwWWOxNDGq[12]);pgMnkaH.open(QMzG[0]+QMzG[" ascii
    $s13 = "function XkqQoSQpS(MNnZkFsrq,VqLVHNQ,spOTyQYF){" fullword ascii
    $s14 = "function Ltiflb(GqpaTg){return GqpaTg.ExpandEnvironmentStrings(FZGGUNovYjncnamwWWOxNDGq[10])}" fullword ascii
    $s15 = "function EXHMa(yGnPPWUo,uJSrnz,SoRvfXeds){tiPJy=yGnPPWUo.split(SoRvfXeds);SobaDYy = FZGGUNovYjncnamwWWOxNDGq[13];for(LzBPvbvi=0;" ascii
    $s16 = "2]+QMzG[3], LfRbVL, false);pgMnkaH.send();}" fullword ascii
    $s17 = "try{fRWDVXv=XkqQoSQpS(ryESZ[RSwp], EJGaIqe() + FZGGUNovYjncnamwWWOxNDGq[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}