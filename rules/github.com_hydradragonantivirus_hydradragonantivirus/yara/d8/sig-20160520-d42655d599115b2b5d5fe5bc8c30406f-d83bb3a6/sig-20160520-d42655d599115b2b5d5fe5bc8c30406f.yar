rule sig_20160520_d42655d599115b2b5d5fe5bc8c30406f {
  meta:
    description = "datamaliciousorder - file 20160520_d42655d599115b2b5d5fe5bc8c30406f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2235b34e8dfa381296421edd70a07ac37b6f327ac010255fc0b97aa821dcced"

  strings:
    $s1  = "function WxdPXfoC(yMwom) {var KYexSUCQ=XLnmxEOfBXHLLqaMqIzdu[2];for(var BINFC=0;BINFC<yMwom;BINFC++){mqypf+=KYexSUCQ.charAt(Math" ascii
    $s2  = "function WxdPXfoC(yMwom) {var KYexSUCQ=XLnmxEOfBXHLLqaMqIzdu[2];for(var BINFC=0;BINFC<yMwom;BINFC++){mqypf+=KYexSUCQ.charAt(Math" ascii
    $s3  = "function tWPbCwLCx(pmUsWampJ,FbnFpfm,qOSIVoeB){" fullword ascii
    $s4  = "try{WMkiGJZ=tWPbCwLCx(jzvcG[vFpQ], tguJioA() + XLnmxEOfBXHLLqaMqIzdu[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function tguJioA() {var SXdn=100000;var drkXQw = 100;return Math.random()*(SXdn-drkXQw)+drkXQw;}" fullword ascii
    $s6  = "function CWdTY(TWhvomVD,BxmJy,BMyvXyilKd){TWhvomVD.open();TWhvomVD.type = 1;TWhvomVD.write(BxmJy);TWhvomVD.position = 0;TWhvomVD" ascii
    $s7  = "function deJiUv(zGSogN){return zGSogN.ExpandEnvironmentStrings(XLnmxEOfBXHLLqaMqIzdu[10])}" fullword ascii
    $s8  = "function odvNT(zGSogN){return new ActiveXObject(zGSogN);}" fullword ascii
    $s9  = "function wnkF(CryJkP,XuGBFrB){QWEg = XLnmxEOfBXHLLqaMqIzdu[11].split(XLnmxEOfBXHLLqaMqIzdu[12]);XuGBFrB.open(QWEg[0]+QWEg[2]+QWE" ascii
    $s10 = ".floor(Math.random()*KYexSUCQ.length));}return mqypf;}" fullword ascii
    $s11 = "if (WMkiGJZ==0) break;" fullword ascii
    $s12 = "function wnkF(CryJkP,XuGBFrB){QWEg = XLnmxEOfBXHLLqaMqIzdu[11].split(XLnmxEOfBXHLLqaMqIzdu[12]);XuGBFrB.open(QWEg[0]+QWEg[2]+QWE" ascii
    $s13 = "function CWdTY(TWhvomVD,BxmJy,BMyvXyilKd){TWhvomVD.open();TWhvomVD.type = 1;TWhvomVD.write(BxmJy);TWhvomVD.position = 0;TWhvomVD" ascii
    $s14 = "g[3], CryJkP, false);XuGBFrB.send();}" fullword ascii
    $s15 = "EaJgY<KcLLrx.length;xpQEaJgY++) {GRiUfvv+=ocAAt[KcLLrx[xpQEaJgY]];}return GRiUfvv.substring(3,GRiUfvv.length);}" fullword ascii
    $s16 = "function aLgSg(syopwaeg,KcLLrx,jIeDVcimU){ocAAt=syopwaeg.split(jIeDVcimU);GRiUfvv = XLnmxEOfBXHLLqaMqIzdu[13];for(xpQEaJgY=0;xpQ" ascii
    $s17 = "function aLgSg(syopwaeg,KcLLrx,jIeDVcimU){ocAAt=syopwaeg.split(jIeDVcimU);GRiUfvv = XLnmxEOfBXHLLqaMqIzdu[13];for(xpQEaJgY=0;xpQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}