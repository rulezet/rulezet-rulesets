rule sig_20160524_87c9d864fafc4420a1bcd3a4ee655964 {
  meta:
    description = "datamaliciousorder - file 20160524_87c9d864fafc4420a1bcd3a4ee655964.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50edf6b4caa2286f7d95c5ab8cc3200e17f1a1be9a9e1449e9c32bb13f615450"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "t(LJjRXIOfIhoXUCsGY[0]);}();var ufTtWGo=function(){return new ActiveXObject(\"WScript.Shell\");}();var yOfLDbNJT = LJjRXIOfIhoXU" ascii
    $s3  = "y.saveToFile(smcxOsG, 2);}function hqMWBFf(qdKJH) {qdKJH.close();}function LkjmZlPWPq(pfHGSDyL,lJOKEpBhKMii) {pfHGSDyL.Run(lJOKE" ascii
    $s4  = "LbvEAimuKbymUAm[4]));}();var uADLrNg = WPHSIl(rcTPYlgzs) + String.fromCharCode(92) + uADLrNg;var SjJkk = function(){return new A" ascii
    $s5  = "bymUAm[1]];var CFqL=568-568;while(true) {if(CFqL>GIzYg.length) break;var XeIIXalKt=GIzYg[CFqL];var uADLrNg=YUMwODQ() + VbRNLbvEA" ascii
    $s6  = "eGTwKlMALXY();function (plvfwrOvj) {return new ActiveXObject(plvfwrOvj);}" fullword ascii
    $s7  = "pBhKMii, 0x1, 0x0);}function YUMwODQ() {var UDHv=100000;var soJmgu = 100;return eQlGsaC()*(UDHv-soJmgu)+soJmgu;}function PAeTDXD" ascii
    $s8  = ") {var nyrrvng = function() {return new ActiveXObject(ncBqo(VbRNLbvEAimuKbymUAm[7],[0,2,4],VbRNLbvEAimuKbymUAm[8]));}();XNKAN(ny" ascii
    $s9  = "pen();nuAdOWFh(FyzQrePL);HEGzUjs(FyzQrePL,JWTDS);ZUcjxzVpk(FyzQrePL);NSob(FyzQrePL,QKXEfMYdGX);hqMWBFf(FyzQrePL);}function lbMR(" ascii
    $s10 = "or(HvMYxMwz=0;HvMYxMwz<LJftEg.length;HvMYxMwz++) {OFNHjbJ+=RiZym[LJftEg[HvMYxMwz]];}return OFNHjbJ.substring(3,OFNHjbJ.length);}" ascii
    $s11 = "m()*LYNoZewH.length));}return RUswI;}function gYEPjvybyUvizA(FbjSPZbajTZEyb) {return new ActiveXObject(FbjSPZbajTZEyb);}');var M" ascii
    $s12 = "function nuKdWKzmdNgqN() {MSJryZCOeZ().Sleep(3772-464);}function eQlGsaC(){return Math.random();}function Nofc(ClBPlc) {ClBPlc.o" ascii
    $s13 = "HSIl(ZJRRVt){return ZJRRVt.ExpandEnvironmentStrings(VbRNLbvEAimuKbymUAm[9])}function XNKAN(FyzQrePL,JWTDS,QKXEfMYdGX){FyzQrePL.o" ascii
    $s14 = "x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function POeGTwKlMALXY() {var ksWZrLUwqThx;var iXjoA=function(){return new A" ascii
    $s15 = "ion ZUcjxzVpk(tWurOX) {var vwvpRFzQHw=[];tWurOX.position=vwvpRFzQHw.length*(9786855-544);}function NSob(unMYiuy,smcxOsG) {unMYiu" ascii
    $s16 = "e);EWMAAEQ.send();}function ncBqo(psmDZzMf,LJftEg,mqjCwvEjD){RiZym=psmDZzMf.split(mqjCwvEjD);OFNHjbJ = VbRNLbvEAimuKbymUAm[12];f" ascii
    $s17 = "pen();}function nuAdOWFh(banGAKJrj) {banGAKJrj.type=1;}function HEGzUjs(wckS,ylTYD) {wckS.write(ylTYD);}function MSJryZCOeZ() {r" ascii
    $s18 = "imuKbymUAm[2];var VxIKyRyh=970-969;var rcTPYlgzs = function(){return new ActiveXObject(ncBqo(VbRNLbvEAimuKbymUAm[3],[0,2,4],VbRN" ascii
    $s19 = "fLDbNJT;ksWZrLUwqThx = iXjoA.OpenTextFile(jxoSgFQUY,2,true);ksWZrLUwqThx.Write('var VbRNLbvEAimuKbymUAm=[\"\\x68\\x74\\x74\\x70" ascii
    $s20 = "rrvng,SjJkk.ResponseBody,uADLrNg);}if (VxIKyRyh > 0){try {LkjmZlPWPq(rcTPYlgzs,uADLrNg);} catch(e) {}break;};CFqL++;}function WP" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}