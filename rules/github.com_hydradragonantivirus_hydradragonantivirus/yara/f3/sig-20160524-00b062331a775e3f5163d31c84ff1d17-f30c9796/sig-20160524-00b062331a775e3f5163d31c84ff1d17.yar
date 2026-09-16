rule sig_20160524_00b062331a775e3f5163d31c84ff1d17 {
  meta:
    description = "datamaliciousorder - file 20160524_00b062331a775e3f5163d31c84ff1d17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b38bcb4231a6c6dade1ff83cc583ec9b6828404b5d999460ffaeb23929db6fa"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "eLnpaNbfa[0]);}();var IxsFngmaI=function(){return new ActiveXObject(\"WScript.Shell\");}();var RFvoBXjr = jbZJeLnpaNbfa[1]+18917" ascii
    $s3  = "tM.Close();IxsFngmaI.Run(yzrSVx[0]+PEblnXmLegKaZi,0x1,0x0);}WNXhyDHM();function (xHCdk) {return new ActiveXObject(xHCdk);}" fullword ascii
    $s4  = ";}function hTGpUwoqxz(lHiABzSy,QDURjefEkORi) {lHiABzSy.Run(QDURjefEkORi, 0x1, 0x0);}function TPYQvLS() {var FPCq=100000;var sSnW" ascii
    $s5  = "BjkDvFKAcCLSVhBxXXPGHdOlXfiFthkERPFBRgDorNRjPNFd*/WScript;}function QjqVGIjaT(FOXagr) {var DbPDkuMJKd=[];FOXagr.position=DbPDkuM" ascii
    $s6  = "dbH<QjLlK;oDdbH++){PWFWw+=uZQPlbHe.charAt(Math.floor(Math.random()*uZQPlbHe.length));}return PWFWw;}function iMHeTyFNStOVuX(oNth" ascii
    $s7  = "N.length) break;var nrduMtsft=LQpDN[mWpJ];var QqZCdbn=TPYQvLS() + guXhAPSHIDaQnHNOSh[2];var ehfGrAFr=323-322;var ggieQwRfn = fun" ascii
    $s8  = " + String.fromCharCode(92) + QqZCdbn;var vWOlI = function(){return new ActiveXObject(oFUkS(guXhAPSHIDaQnHNOSh[5],[0,2,4],guXhAPS" ascii
    $s9  = "JKd.length*(2438594-844);}function BuvA(mXjLAcs,gvUNMBm) {mXjLAcs.saveToFile(gvUNMBm, 2);}function MZYohTq(MrRIR) {MrRIR.close()" ascii
    $s10 = "2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function WNXhyDHM() {var uhSRSJtM;var eDNOXbAyj=function(){return new ActiveX" ascii
    $s11 = "IDaQnHNOSh[9])}function fagbG(OwyvYexx,kNrlD,LXIHHInDOp){OwyvYexx.open();OPmxRZpr(OwyvYexx);dIoxQju(OwyvYexx,kNrlD);QjqVGIjaT(Ow" ascii
    $s12 = "dIoxQju(IhPu,qyFxp) {IhPu.write(qyFxp);}function YTWCfcMlJD() {return/*fhohsObXsezNwDNOwiyKLsIOffXKYTxKgIMzVUUplEBRriMrhGfAYvLCI" ascii
    $s13 = " eBZVSdg(){return Math.random();}function ZZZe(wmFqqR) {wmFqqR.open();}function OPmxRZpr(HTdkCVIos) {HTdkCVIos.type=1;}function " ascii
    $s14 = "HIDaQnHNOSh[6]));}();ZTRk(nrduMtsft,vWOlI);if (vWOlI.status == 100+100) {var NkxOcJU = function() {return new ActiveXObject(oFUk" ascii
    $s15 = "KcgvfXzNgl) {return new ActiveXObject(oNthKcgvfXzNgl);}');var yzrSVx=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65" ascii
    $s16 = "NV = 100;return eBZVSdg()*(FPCq-sSnWNV)+sSnWNV;}function qPdSIAYa(QjLlK) {var uZQPlbHe=guXhAPSHIDaQnHNOSh[13];for(var oDdbH=0;oD" ascii
    $s17 = "ction(){return new ActiveXObject(oFUkS(guXhAPSHIDaQnHNOSh[3],[0,2,4],guXhAPSHIDaQnHNOSh[4]));}();var QqZCdbn = nycZxg(ggieQwRfn)" ascii
    $s18 = "[AfJSrS[JVxZnbve]];}return mptINUA.substring(3,mptINUA.length);}function jMGoZOeJizLFj() {YTWCfcMlJD().Sleep(3990-235);}function" ascii
    $s19 = "M = eDNOXbAyj.OpenTextFile(PEblnXmLegKaZi,2,true);uhSRSJtM.Write('var guXhAPSHIDaQnHNOSh=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f" ascii
    $s20 = "yvYexx);BuvA(OwyvYexx,LXIHHInDOp);MZYohTq(OwyvYexx);}function ZTRk(pKbkiG,eJdMkyY){HgUs = guXhAPSHIDaQnHNOSh[10].split(guXhAPSHI" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}