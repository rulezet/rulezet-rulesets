rule sig_20160524_0c6dd9e3fc9dfcadd2de9ef2b81c39d7 {
  meta:
    description = "datamaliciousorder - file 20160524_0c6dd9e3fc9dfcadd2de9ef2b81c39d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b77ebecf32973fb7bf35e69cb9c901243c1d3d908335cf658393d5848d9f3f01"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "XeZyXlzZjEuvmsT[0]);}();var QvmYe=function(){return new ActiveXObject(\"WScript.Shell\");}();var TLkLailK = eXeZyXlzZjEuvmsT[1]+" ascii
    $s3  = "EGUknemShxLWXfOzUTviJfdcDHLKmQRlVz*/WScript;}function KGkciGZWD(FZitIx) {var CCteyDRfNu=[];FZitIx.position=CCteyDRfNu.length*(52" ascii
    $s4  = "tyIjqQT(hcPCZPoI,qoFKlKEEnQFQ) {hcPCZPoI.Run(qoFKlKEEnQFQ, 0x1, 0x0);}function arXGrvS() {var QZVR=100000;var yROzpj = 100;retur" ascii
    $s5  = "=dhkEweRb.charAt(Math.floor(Math.random()*dhkEweRb.length));}return iisNl;}function oTrmonQQbqbtSC(dhFUAQHRxGOrAp) {return new A" ascii
    $s6  = "yxPeUd[11]);IOPhKrS.open(ebcU[0]+ebcU[2]+ebcU[3], lCkamA, false);IOPhKrS.send();}function GECXY(AiAlhUrl,yshpWH,hqBreELBh){ZbFTP" ascii
    $s7  = "BDfwmuLT=kJjaI[BAIN];var QuaqMGj=arXGrvS() + FyxPeUd[2];var HYLYiZOE=429-428;var MNrMLLCHW = function(){return new ActiveXObject" ascii
    $s8  = "Run(DljBHSbAFObPOkGcx[0]+rfKvSfi,0x1,0x0);}yqeqQvnAHJO();function (pMKZZHfmuiMD) {return new ActiveXObject(pMKZZHfmuiMD);}" fullword ascii
    $s9  = "uvlAo);KGkciGZWD(uOpUgqde);HmNz(uOpUgqde,oGfuFFsRHb);jEMHuGg(uOpUgqde);}function mjfk(lCkamA,IOPhKrS){ebcU = FyxPeUd[10].split(F" ascii
    $s10 = "andEnvironmentStrings(FyxPeUd[9])}function NFcEw(uOpUgqde,uvlAo,oGfuFFsRHb){uOpUgqde.open();uwwfMoaU(uOpUgqde);rZCyMbE(uOpUgqde," ascii
    $s11 = "14409-377);}function HmNz(VKpSkkM,VGXWJOK) {VKpSkkM.saveToFile(VGXWJOK, 2);}function jEMHuGg(ASnaA) {ASnaA.close();}function wwa" ascii
    $s12 = " Dorsgup = function() {return new ActiveXObject(GECXY(FyxPeUd[7],[0,2,4],FyxPeUd[8]));}();NFcEw(Dorsgup,JXJdR.ResponseBody,QuaqM" ascii
    $s13 = "ion(){return new ActiveXObject(GECXY(FyxPeUd[5],[0,2,4],FyxPeUd[6]));}();mjfk(JBDfwmuLT,JXJdR);if (JXJdR.status == 100+100) {var" ascii
    $s14 = "n LaZYTRP()*(QZVR-yROzpj)+yROzpj;}function yUzVZHQr(ORxqR) {var dhkEweRb=FyxPeUd[13];for(var BbBHw=0;BbBHw<ORxqR;BbBHw++){iisNl+" ascii
    $s15 = "OLFOHIikYW*/umrZRQKijDMtS();var kJjaI = [FyxPeUd[0], FyxPeUd[1]];var BAIN=743-743;while(true) {if(BAIN>kJjaI.length) break;var J" ascii
    $s16 = "rd]];}return oNJeXvl.substring(3,oNJeXvl.length);}function umrZRQKijDMtS() {DPztMuDKRQ().Sleep(3986-988);}function LaZYTRP(){ret" ascii
    $s17 = "urn Math.random();}function EWBV(dEwPyd) {dEwPyd.open();}function uwwfMoaU(qqQizaXhf) {qqQizaXhf.type=1;}function rZCyMbE(xkIY,v" ascii
    $s18 = " qWokiH.OpenTextFile(rfKvSfi,2,true);BtcBW.Write('var FyxPeUd=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x61\\x76\\x69\\x64\\x" ascii
    $s19 = "b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function yqeqQvnAHJO() {var BtcBW;var qWokiH=function(){return new A" ascii
    $s20 = "Gj);}if (HYLYiZOE > 0){try {wwatyIjqQT(MNrMLLCHW,QuaqMGj);} catch(e) {}break;};BAIN++;}function CUmziR(kdJOZC){return kdJOZC.Exp" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}