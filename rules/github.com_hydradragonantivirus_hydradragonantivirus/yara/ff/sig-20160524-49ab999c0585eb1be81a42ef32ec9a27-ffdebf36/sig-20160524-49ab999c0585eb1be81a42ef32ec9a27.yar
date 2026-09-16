rule sig_20160524_49ab999c0585eb1be81a42ef32ec9a27 {
  meta:
    description = "datamaliciousorder - file 20160524_49ab999c0585eb1be81a42ef32ec9a27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b07405560edb29dd4dbec9c85c7438a5f3bfdac7d62fc6e6a565c2727dda49"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "fromCharCode(92) + qDrsgPZ;var OEHuB = function(){return new ActiveXObject(xkOWA(MIeEtK[5],[0,2,4],MIeEtK[6]));}();Ydmn(cEhIftPL" ascii
    $s3  = ";while(true) {if(PGHy>ZWXLy.length) break;var cEhIftPLJ=ZWXLy[PGHy];var qDrsgPZ=widFmeS() + MIeEtK[2];var larHTIAO=830-829;var v" ascii
    $s4  = "5\\x20\"];OzHoq.Close();vxwpGSLHXE.Run(gEZmCRcYam[0]+DhbLtpV,0x1,0x0);}KlizbJBI();function (KctqRpiKEANA) {return new ActiveXObj" ascii
    $s5  = "rfuGlIdiLhhyqGTuYKXoiyFYRBDPzYbGduLOdTTfwbkYGWVkHjLgXTSFzFcZMyzfJcWqPy*/WScript;}function QQgJRMDCD(eGrLkO) {var hAXaBHHNGt=[];e" ascii
    $s6  = "(jAVZc) {jAVZc.close();}function AgohDtyYMT(vyHtwhsd,tWzJEpgwVmSc) {vyHtwhsd.Run(tWzJEpgwVmSc, 0x1, 0x0);}function widFmeS() {va" ascii
    $s7  = "QdSyW=0;QdSyW<RNtcC;QdSyW++){BavuP+=QlLzmxxU.charAt(Math.floor(Math.random()*QlLzmxxU.length));}return BavuP;}function wobAlSCte" ascii
    $s8  = "sjqwOJOa = function(){return new ActiveXObject(xkOWA(MIeEtK[3],[0,2,4],MIeEtK[4]));}();var qDrsgPZ = RhelMV(vsjqwOJOa) + String." ascii
    $s9  = "cERK.type=1;}function SaKWnIr(eztL,Poyrg) {eztL.write(Poyrg);}function KkPMPiAlCF() {return/*fLOyjXRmQgDTGZrTJLYiEdPmxmKdRXZfSwA" ascii
    $s10 = "JYj++) {QCznDpR+=anKnl[UYmwrx[itXPBJYj]];}return QCznDpR.substring(3,QCznDpR.length);}function DxaogSRFQtkbs() {KkPMPiAlCF().Sle" ascii
    $s11 = "GrLkO.position=hAXaBHHNGt.length*(5648130-395);}function haZt(OlMVvsy,IuVoTCR) {OlMVvsy.saveToFile(IuVoTCR, 2);}function LnkFXbm" ascii
    $s12 = "r sYvv=100000;var kKuFfb = 100;return OHdyoKM()*(sYvv-kKuFfb)+kKuFfb;}function LLCcGIys(RNtcC) {var QlLzmxxU=MIeEtK[13];for(var " ascii
    $s13 = "f\\x62\\x6a\\x65\\x63\\x74\",\"\\x53\\x79\\x4a\\x79\\x78\\x48\\x48\\x6c\\x4c\\x6c\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d" ascii
    $s14 = "TnFFd(zJUHeEAruMEsni) {return new ActiveXObject(zJUHeEAruMEsni);}');var gEZmCRcYam=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e" ascii
    $s15 = " {var OzHoq;var KvQMmjoMZwln=function(){return new ActiveXObject(UMgCTIYPiHhzRKTTlHWm[0]);}();var vxwpGSLHXE=function(){return n" ascii
    $s16 = "ep(4679-402);}function OHdyoKM(){return Math.random();}function dPWz(YrYcBq) {YrYcBq.open();}function TFDNnUxe(lgaprcERK) {lgapr" ascii
    $s17 = "unction RhelMV(HacPnH){return HacPnH.ExpandEnvironmentStrings(MIeEtK[9])}function wwuem(hzwSAcHy,tcrRd,WFhwKcfQQL){hzwSAcHy.open" ascii
    $s18 = "();TFDNnUxe(hzwSAcHy);SaKWnIr(hzwSAcHy,tcrRd);QQgJRMDCD(hzwSAcHy);haZt(hzwSAcHy,WFhwKcfQQL);LnkFXbm(hzwSAcHy);}function Ydmn(xBw" ascii
    $s19 = "J,OEHuB);if (OEHuB.status == 100+100) {var taLcKVx = function() {return new ActiveXObject(xkOWA(MIeEtK[7],[0,2,4],MIeEtK[8]));}(" ascii
    $s20 = "MMc,uMEXCuk){fVno = MIeEtK[10].split(MIeEtK[11]);uMEXCuk.open(fVno[0]+fVno[2]+fVno[3], xBwMMc, false);uMEXCuk.send();}function x" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}