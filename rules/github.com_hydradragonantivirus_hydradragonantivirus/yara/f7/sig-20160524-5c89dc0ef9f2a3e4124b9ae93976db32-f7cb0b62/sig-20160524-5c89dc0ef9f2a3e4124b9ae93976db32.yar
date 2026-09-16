rule sig_20160524_5c89dc0ef9f2a3e4124b9ae93976db32 {
  meta:
    description = "datamaliciousorder - file 20160524_5c89dc0ef9f2a3e4124b9ae93976db32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb369c48959291fab6b47d13ebd2e5da98d1cc51a983dfece613284b5193c5b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "zsZMXkNwf=function(){return new ActiveXObject(\"WScript.Shell\");}();var GapuGYsshMyst = bJizsWgaU[1]+15220+bJizsWgaU[2];var LEk" ascii
    $s3  = "vzmIHHcYroEeVzeUtSnLiypvoWXqisxnPpyFIUokKKCtuQBYKS*/WScript;}function XpIvbfQvb(kDWhvU) {var ChdlskcDWd=[];kDWhvU.position=Chdls" ascii
    $s4  = "];pjuPHZAWNEOYY.Close();zsZMXkNwf.Run(OiBxtDuIk[0]+LEkbZ,0x1,0x0);}NFxHUpsOBu();function (QQewFmTXokiY) {return new ActiveXObjec" ascii
    $s5  = "();}function nPfTiHAzoZ(zMLbUGdz,eEvEUGtcHjbd) {zMLbUGdz.Run(eEvEUGtcHjbd, 0x1, 0x0);}function fCUCcLv() {var Zzbd=100000;var Zc" ascii
    $s6  = "=0;IdCQF<DiyFs;IdCQF++){vnLND+=CpdfFaJA.charAt(Math.floor(Math.random()*CpdfFaJA.length));}return vnLND;}function fLSlKecCwgmlwc" ascii
    $s7  = "DoGK[jwdr];var gMYxrML=fCUCcLv() + xBzYOKlrBrqDNBbNWFiAc[2];var rSTwETae=707-706;var QhzgfSgDd = function(){return new ActiveXOb" ascii
    $s8  = "(92) + gMYxrML;var nseTT = function(){return new ActiveXObject(jQDUx(xBzYOKlrBrqDNBbNWFiAc[5],[0,2,4],xBzYOKlrBrqDNBbNWFiAc[6]))" ascii
    $s9  = "kcDWd.length*(5812839-824);}function ItvW(NGsBKNT,eqOCqXh) {NGsBKNT.saveToFile(eqOCqXh, 2);}function zwxQohi(nZKWy) {nZKWy.close" ascii
    $s10 = "\\x45\\x4d\\x50\\x25\"];function NFxHUpsOBu() {var pjuPHZAWNEOYY;var LinVh=function(){return new ActiveXObject(bJizsWgaU[0]);}()" ascii
    $s11 = "on IkMaOiR(){return Math.random();}function tuvl(UZcgvA) {UZcgvA.open();}function HnnwqRoM(IFQTMMMRj) {IFQTMMMRj.type=1;}functio" ascii
    $s12 = ";ItvW(UKQalPMk,htIdSNTOtB);zwxQohi(UKQalPMk);}function jliL(RkkXAe,YqyKvuu){vaqB = xBzYOKlrBrqDNBbNWFiAc[10].split(xBzYOKlrBrqDN" ascii
    $s13 = "BbNWFiAc[11]);YqyKvuu.open(vaqB[0]+vaqB[2]+vaqB[3], RkkXAe, false);YqyKvuu.send();}function jQDUx(yqFoeMkn,tkgADA,sFrbsHXFg){SwF" ascii
    $s14 = "libO = 100;return IkMaOiR()*(Zzbd-ZclibO)+ZclibO;}function yDcqAGCL(DiyFs) {var CpdfFaJA=xBzYOKlrBrqDNBbNWFiAc[13];for(var IdCQF" ascii
    $s15 = "n ZsddEBC(ZkEM,ceuGQ) {ZkEM.write(ceuGQ);}function kmYuVnomFl() {return/*DqHEWRSrXBEVLGJpSPzYwqSUbUfBOKfRmAjqABjVlxyfvBSSKxLGkxT" ascii
    $s16 = ";}();jliL(JjpaYyBLT,nseTT);if (nseTT.status == 100+100) {var VRDjESa = function() {return new ActiveXObject(jQDUx(xBzYOKlrBrqDNB" ascii
    $s17 = "iAc[9])}function EDDTb(UKQalPMk,ToLSK,htIdSNTOtB){UKQalPMk.open();HnnwqRoM(UKQalPMk);ZsddEBC(UKQalPMk,ToLSK);XpIvbfQvb(UKQalPMk)" ascii
    $s18 = "eF[tkgADA[lfEfwbPn]];}return BQBocQd.substring(3,BQBocQd.length);}function VsgUXrECsoETq() {kmYuVnomFl().Sleep(2757-208);}functi" ascii
    $s19 = "= [xBzYOKlrBrqDNBbNWFiAc[0], xBzYOKlrBrqDNBbNWFiAc[1]];var jwdr=418-418;while(true) {if(jwdr>ZDoGK.length) break;var JjpaYyBLT=Z" ascii
    $s20 = "(qkoEEYdWVzuRGl) {return new ActiveXObject(qkoEEYdWVzuRGl);}');var OiBxtDuIk=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}