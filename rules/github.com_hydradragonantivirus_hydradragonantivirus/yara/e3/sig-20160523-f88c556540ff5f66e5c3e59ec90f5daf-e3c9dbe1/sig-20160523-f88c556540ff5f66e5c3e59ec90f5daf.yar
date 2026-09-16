rule sig_20160523_f88c556540ff5f66e5c3e59ec90f5daf {
  meta:
    description = "datamaliciousorder - file 20160523_f88c556540ff5f66e5c3e59ec90f5daf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca5964dcd0a3bf4ceb03c4fa0ea3d6a6130faba1dab3eeab0ed769dc95bc71b"

  strings:
    $s1  = "function TCLnRhLZtI() {return/*YCLMLiKXXAfUZpciiiqCUVYjAAmjGeZeNfUVsmqciZrWuxMErzzTAACQbvoFvAMUnhNHrfkwqevtLyevlUGGeIoHVqhjYRcYV" ascii
    $s2  = "function QVYFfNYdml(MwsOuHWF,EwNYRvISewBH) {MwsOuHWF.Run(EwNYRvISewBH, 0x1, 0x0);}" fullword ascii
    $s3  = "TUNf.length;tGxtogZG++) {uRFBWWp+=PjDII[pZTUNf[tGxtogZG]];}return uRFBWWp.substring(3,uRFBWWp.length);}" fullword ascii
    $s4  = "function BrICyfSm(eGhzh) {var vAigoBNt=yLuaLaJVyPvNS[13];for(var HpWHX=0;HpWHX<eGhzh;HpWHX++){pMzcA+=vAigoBNt.charAt(Math.floor(" ascii
    $s5  = "function BrICyfSm(eGhzh) {var vAigoBNt=yLuaLaJVyPvNS[13];for(var HpWHX=0;HpWHX<eGhzh;HpWHX++){pMzcA+=vAigoBNt.charAt(Math.floor(" ascii
    $s6  = "function UbIzH(mZoSmdXQ,pZTUNf,AKWohwWRG){PjDII=mZoSmdXQ.split(AKWohwWRG);uRFBWWp = yLuaLaJVyPvNS[12];for(tGxtogZG=0;tGxtogZG<pZ" ascii
    $s7  = "function BwWKwPyzH(ovmxQa) {var qpxIolbALx=[];ovmxQa.position=qpxIolbALx.length*(4791962-740);}" fullword ascii
    $s8  = "function CDxg(viIBxgB,hcciUIG) {viIBxgB.saveToFile(hcciUIG, 2);}" fullword ascii
    $s9  = "function vjcZIde() {var BNKP=100000;var JVYhrF = 100;return IwqelVQ()*(BNKP-JVYhrF)+JVYhrF;}" fullword ascii
    $s10 = "function jgFl(PIhkYd) {PIhkYd.open();}" fullword ascii
    $s11 = "function MnBX(DQeRqZ,tfuoBXQ){msYu = yLuaLaJVyPvNS[10].split(yLuaLaJVyPvNS[11]);tfuoBXQ.open(msYu[0]+msYu[2]+msYu[3], DQeRqZ, fa" ascii
    $s12 = "function UbIzH(mZoSmdXQ,pZTUNf,AKWohwWRG){PjDII=mZoSmdXQ.split(AKWohwWRG);uRFBWWp = yLuaLaJVyPvNS[12];for(tGxtogZG=0;tGxtogZG<pZ" ascii
    $s13 = "function GBdNbW(EbpUKz){return EbpUKz.ExpandEnvironmentStrings(yLuaLaJVyPvNS[9])}" fullword ascii
    $s14 = "function tXnPLaqF(yPtLUbqWn) {yPtLUbqWn.type=1;}" fullword ascii
    $s15 = "function aocUU(EbpUKz){return new ActiveXObject(EbpUKz);}" fullword ascii
    $s16 = "function IwqelVQ(){return Math.random();}" fullword ascii
    $s17 = "function bMNZL(bJnTGfAn,ZBVRr,WKZQoLyRNQ){jgFl(bJnTGfAn);tXnPLaqF(bJnTGfAn);ikjwwDK(bJnTGfAn,ZBVRr);BwWKwPyzH(bJnTGfAn);CDxg(bJn" ascii
    $s18 = "function MnBX(DQeRqZ,tfuoBXQ){msYu = yLuaLaJVyPvNS[10].split(yLuaLaJVyPvNS[11]);tfuoBXQ.open(msYu[0]+msYu[2]+msYu[3], DQeRqZ, fa" ascii
    $s19 = "function zBXZAOOIhMUFJ() {TCLnRhLZtI().Sleep(2369480-236);}" fullword ascii
    $s20 = "function mExZCiO(ncLeg) {ncLeg.close();}" fullword ascii

  condition:
    uint16(0) == 0x0527 and
    8 of them
}