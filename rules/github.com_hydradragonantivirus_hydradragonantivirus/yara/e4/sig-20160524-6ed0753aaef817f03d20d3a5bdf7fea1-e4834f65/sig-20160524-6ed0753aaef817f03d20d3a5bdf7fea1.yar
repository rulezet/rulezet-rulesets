rule sig_20160524_6ed0753aaef817f03d20d3a5bdf7fea1 {
  meta:
    description = "datamaliciousorder - file 20160524_6ed0753aaef817f03d20d3a5bdf7fea1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2b9ee7567e73086febb3001f28b516e07b88eef3912d42b8bc3bc73d87ba975"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "function(){return new ActiveXObject(\"WScript.Shell\");}();var LPUjVISkLVtE = yGxkoNDTkHlNalpOHcTRw[1]+10731+yGxkoNDTkHlNalpOHcT" ascii
    $s3  = "cDBNE*/WScript;}function jgrIOqKvK(sItvry) {var uSRQPBZVxt=[];sItvry.position=uSRQPBZVxt.length*(2392967-953);}function sAJT(cPs" ascii
    $s4  = ") {BCpCCTHj.Run(WqKfNepoFUQi, 0x1, 0x0);}function tKteDqs() {var mYKn=100000;var lvRLNn = 100;return rYWDlpt()*(mYKn-lvRLNn)+lvR" ascii
    $s5  = "a.Run(HXYBGVNFNyXRTtnnZk[0]+HzIzwWlc,0x1,0x0);}ZXpDFXocfeiovQ();function (vjOBHRGT) {return new ActiveXObject(vjOBHRGT);}" fullword ascii
    $s6  = "ocfeiovQ() {var wechkKNgaUYe;var DkLWpIuRrJ=function(){return new ActiveXObject(yGxkoNDTkHlNalpOHcTRw[0]);}();var getdpoCnPNcFa=" ascii
    $s7  = "jeCelbzWOWKu[4]));}();var nzSoRvf = hMnFKv(vbvitiPJy) + String.fromCharCode(92) + nzSoRvf;var KrxOX = function(){return new Acti" ascii
    $s8  = "ar iJQL=475-475;while(true) {if(iJQL>TcunB.length) break;var PPWUouJSr=TcunB[iJQL];var nzSoRvf=tKteDqs() + PlwISqnaAYjeCelbzWOWK" ascii
    $s9  = "aAYjeCelbzWOWKu[12];for(tuLOyEHF=0;tuLOyEHF<ComkVz.length;tuLOyEHF++) {BEaJLnA+=MgmGB[ComkVz[tuLOyEHF]];}return BEaJLnA.substrin" ascii
    $s10 = "N[3], MadAPB, false);ZANFSkE.send();}function PlWpo(VSdBKOzu,ComkVz,ERPZmFGTu){MgmGB=VSdBKOzu.split(ERPZmFGTu);BEaJLnA = PlwISqn" ascii
    $s11 = "ssA(UyzPMP) {UyzPMP.open();}function DlZbVlNv(sOGHotJYz) {sOGHotJYz.type=1;}function XAdsamk(LAwc,VVkSO) {LAwc.write(VVkSO);}fun" ascii
    $s12 = "At(Math.floor(Math.random()*nkaHQMzG.length));}return fjfVT;}function DobPDQJYjvXzNB(VEghiYHMPTinua) {return new ActiveXObject(V" ascii
    $s13 = "100) {var qeFWgFZ = function() {return new ActiveXObject(PlWpo(PlwISqnaAYjeCelbzWOWKu[7],[0,2,4],PlwISqnaAYjeCelbzWOWKu[8]));}()" ascii
    $s14 = "u[2];var XedsLzBP=960-959;var vbvitiPJy = function(){return new ActiveXObject(PlWpo(PlwISqnaAYjeCelbzWOWKu[3],[0,2,4],PlwISqnaAY" ascii
    $s15 = "4\\x65\\x6d\\x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x56\\x65\\x55\\x75\\x4b\\x4a\\x46\\x76\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45" ascii
    $s16 = "g(3,BEaJLnA.length);}function HFgRafRGGIEqW() {FYcMqbtxSp().Sleep(4757-804);}function rYWDlpt(){return Math.random();}function T" ascii
    $s17 = "aHAO,lnSRAxD) {cPsaHAO.saveToFile(lnSRAxD, 2);}function SqsRIGC(vGVfA) {vGVfA.close();}function DfHRSLnFqL(BCpCCTHj,WqKfNepoFUQi" ascii
    $s18 = "nction hMnFKv(CXJNzF){return CXJNzF.ExpandEnvironmentStrings(PlwISqnaAYjeCelbzWOWKu[9])}function FhMIp(yVFhHpzg,kFHJo,cVQxrHYQLJ" ascii
    $s19 = "LNn;}function jPcsLfRb(VLpgM) {var nkaHQMzG=PlwISqnaAYjeCelbzWOWKu[13];for(var XGWfO=0;XGWfO<VLpgM;XGWfO++){fjfVT+=nkaHQMzG.char" ascii
    $s20 = "UYe = DkLWpIuRrJ.OpenTextFile(HzIzwWlc,2,true);wechkKNgaUYe.Write('var PlwISqnaAYjeCelbzWOWKu=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}