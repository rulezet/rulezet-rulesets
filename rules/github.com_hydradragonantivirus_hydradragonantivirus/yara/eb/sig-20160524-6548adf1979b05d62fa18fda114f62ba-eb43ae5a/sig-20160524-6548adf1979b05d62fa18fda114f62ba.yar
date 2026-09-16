rule sig_20160524_6548adf1979b05d62fa18fda114f62ba {
  meta:
    description = "datamaliciousorder - file 20160524_6548adf1979b05d62fa18fda114f62ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93f626e30d69f38050379e32203f665471490b9d81b02c5c0340c8cdb31b54a3"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "{return new ActiveXObject(QGpxOKnolm[0]);}();var EVJSonGYmseBWc=function(){return new ActiveXObject(\"WScript.Shell\");}();var u" ascii
    $s3  = "OlnS) {PBZVxtsA.Run(JTcPsaHAOlnS, 0x1, 0x0);}function JznTHPR() {var Swpr=100000;var XGMgGq = 100;return VSdBKOz()*(Swpr-XGMgGq)" ascii
    $s4  = "UzqpLBhEO*/WScript;}function lptTssAUy(zPMPDl) {var ZbVlNvsOGH=[];zPMPDl.position=ZbVlNvsOGH.length*(1950056-780);}function otJY" ascii
    $s5  = "+XGMgGq;}function paTgLtif(lbwUB) {var qjCRgsJT=GZmGV[13];for(var MxuTc=0;MxuTc<lbwUB;MxuTc++){unBtK+=qjCRgsJT.charAt(Math.floor" ascii
    $s6  = "LpgMn=VwiNc[acfF];var kaHQMzG=JznTHPR() + GZmGV[2];var XGWfOfjf=202-201;var VTEdvhYYU = function(){return new ActiveXObject(QLJg" ascii
    $s7  = "Y(GZmGV[3],[0,2,4],GZmGV[4]));}();var kaHQMzG = XBuVDR(VTEdvhYYU) + String.fromCharCode(92) + kaHQMzG;var yGnPP = function(){ret" ascii
    $s8  = "HsaXxc);otJY(DAHsaXxc,JQLdwcFiCX);kSOjgrI(DAHsaXxc);}function JNzF(hMnFKv,pcFIFBB){OFhM = GZmGV[10].split(GZmGV[11]);pcFIFBB.ope" ascii
    $s9  = "on uCom(kVzERP) {kVzERP.open();}function ZmFGTutu(LOyEHFMgm) {LOyEHFMgm.type=1;}function GBBEaJL(nACk,urYWD) {nACk.write(urYWD);" ascii
    $s10 = "BKIgEjDmKYy*/dDBhpwfwWcNLl();var VwiNc = [GZmGV[0], GZmGV[1]];var acfF=196-196;while(true) {if(acfF>VwiNc.length) break;var fRbV" ascii
    $s11 = "}function RAxDSqsRIG() {return/*CvGVfADfHRSLnFqLBCpCCTHjWqKfNepoFUQiFYcMqbtxSpHpPyiMmOQMPYVOBlqPdntpyqVlsfpcQSsNwnvQpDsiayAqJlLk" ascii
    $s12 = "ings(GZmGV[9])}function fWEgW(DAHsaXxc,EsHni,JQLdwcFiCX){DAHsaXxc.open();ZmFGTutu(DAHsaXxc);GBBEaJL(DAHsaXxc,EsHni);lptTssAUy(DA" ascii
    $s13 = "(zXAdsam,kLAwcVV) {zXAdsam.saveToFile(kLAwcVV, 2);}function kSOjgrI(OqKvK) {OqKvK.close();}function sItvryuSRQ(PBZVxtsA,JTcPsaHA" ascii
    $s14 = "tring(3,pNiWXPl.length);}function dDBhpwfwWcNLl() {RAxDSqsRIG().Sleep(4815-391);}function VSdBKOz(){return Math.random();}functi" ascii
    $s15 = "n(OFhM[0]+OFhM[2]+OFhM[3], hMnFKv, false);pcFIFBB.send();}function QLJgY(UsMadAPB,ZANFSk,ERuUNrQym){PgpMn=UsMadAPB.split(ERuUNrQ" ascii
    $s16 = "fromCharCode(92)+uDyKcjpFupYxO;JPVFHkmyOuQu = kpDsvN.OpenTextFile(pUgbfyVUPyqZUj,2,true);JPVFHkmyOuQu.Write('var GZmGV=[\"\\x68" ascii
    $s17 = "nction() {return new ActiveXObject(QLJgY(GZmGV[7],[0,2,4],GZmGV[8]));}();fWEgW(WUouJSr,yGnPP.ResponseBody,kaHQMzG);}if (XGWfOfjf" ascii
    $s18 = "TWLKPjqLrYRXhurDsdXwyI[0]+pUgbfyVUPyqZUj,0x1,0x0);}qgSmPkktJmFUd();function (HMQHBBMqShGCie) {return new ActiveXObject(HMQHBBMqS" ascii
    $s19 = "(Math.random()*qjCRgsJT.length));}return unBtK;}function hGuSWDqHkldsbR(zXagXTnqnfseOf) {return new ActiveXObject(zXagXTnqnfseOf" ascii
    $s20 = "ym);pNiWXPl = GZmGV[12];for(JSmAYLdA=0;JSmAYLdA<ZANFSk.length;JSmAYLdA++) {pNiWXPl+=PgpMn[ZANFSk[JSmAYLdA]];}return pNiWXPl.subs" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}