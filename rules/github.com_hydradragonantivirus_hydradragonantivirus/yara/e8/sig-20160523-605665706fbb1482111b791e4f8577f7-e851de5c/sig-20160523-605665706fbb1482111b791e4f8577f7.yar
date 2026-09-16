rule sig_20160523_605665706fbb1482111b791e4f8577f7 {
  meta:
    description = "datamaliciousorder - file 20160523_605665706fbb1482111b791e4f8577f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef2fa693bb2b5bd6472c79222b6d2b8d546b81d0a6f71e22e97efae00f7fd53"

  strings:
    $s1  = "function zriwtFuhNs() {return/*qjVFPOEqYbrUOmAYImxzIXaAcQsLMBNAwSxjWOoozFvFDIzXbYDheCBjVOaymtFzhFoqbjefboOPbACHxXCoOninrReRhkYxi" ascii
    $s2  = "function KcFoyfJAfs(brgsmjvA,vLmwQRJGuzNv) {brgsmjvA.Run(vLmwQRJGuzNv, 0x1, 0x0);}" fullword ascii
    $s3  = "function tfebOJjE(zzSLB) {var nSLWZAhH=evAhEwgqfsxP[13];for(var plGbU=0;plGbU<zzSLB;plGbU++){FqVTy+=nSLWZAhH.charAt(Math.floor(M" ascii
    $s4  = "function SIAOlwJ() {var qHzE=100000;var KuIRcU = 100;return QyWHJji()*(qHzE-KuIRcU)+KuIRcU;}" fullword ascii
    $s5  = "function tfebOJjE(zzSLB) {var nSLWZAhH=evAhEwgqfsxP[13];for(var plGbU=0;plGbU<zzSLB;plGbU++){FqVTy+=nSLWZAhH.charAt(Math.floor(M" ascii
    $s6  = "ath.random()*nSLWZAhH.length));}return FqVTy;}" fullword ascii
    $s7  = "xrj.length;iqgnFxKH++) {HiwqNYG+=IHBqv[AcSxrj[iqgnFxKH]];}return HiwqNYG.substring(3,HiwqNYG.length);}" fullword ascii
    $s8  = "function ZQtsuSU(xipHw) {xipHw.close();}" fullword ascii
    $s9  = "function zPRWmfNQ(iuLJjDfVt) {iuLJjDfVt.type=1;}" fullword ascii
    $s10 = "function cxbI(TPvTEH,Vrhbksb){DOLJ = evAhEwgqfsxP[10].split(evAhEwgqfsxP[11]);Vrhbksb.open(DOLJ[0]+DOLJ[2]+DOLJ[3], TPvTEH, fals" ascii
    $s11 = "function QyWHJji(){return Math.random();}" fullword ascii
    $s12 = "function VYRAa(SuNQrB){return new ActiveXObject(SuNQrB);}" fullword ascii
    $s13 = "function cxbI(TPvTEH,Vrhbksb){DOLJ = evAhEwgqfsxP[10].split(evAhEwgqfsxP[11]);Vrhbksb.open(DOLJ[0]+DOLJ[2]+DOLJ[3], TPvTEH, fals" ascii
    $s14 = "function sdLAhi(SuNQrB){return SuNQrB.ExpandEnvironmentStrings(evAhEwgqfsxP[9])}" fullword ascii
    $s15 = "function fXsZREsZZ(aiEuYa) {var iGKSksUliY=[];aiEuYa.position=iGKSksUliY.length*(6609055-828);}" fullword ascii
    $s16 = "function PKWxO(YNcIHZtC,AcSxrj,jUrKQvytT){IHBqv=YNcIHZtC.split(jUrKQvytT);HiwqNYG = evAhEwgqfsxP[12];for(iqgnFxKH=0;iqgnFxKH<AcS" ascii
    $s17 = "function zRrMPxP(avmr,OJCUP) {avmr.write(OJCUP);}" fullword ascii
    $s18 = "function aODmanCJnyUYz() {zriwtFuhNs().Sleep(2505352-126);}" fullword ascii
    $s19 = "function sTQB(fQmeEu) {fQmeEu.open();}" fullword ascii
    $s20 = "if(tFJH>WMUmO.length) break;" fullword ascii

  condition:
    uint16(0) == 0x1527 and
    8 of them
}