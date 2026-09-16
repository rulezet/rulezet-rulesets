rule sig_20160524_e2a887bd68d701136c4497cb86c8b935 {
  meta:
    description = "datamaliciousorder - file 20160524_e2a887bd68d701136c4497cb86c8b935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9233e09e90f397ceaece21983105e8c79e31e316969f7ed56cbb1188c27f19e3"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ApB=function(){return new ActiveXObject(\"WScript.Shell\");}();var qgtzMRwqko = TvXXItI[1]+18741+TvXXItI[2];var QvglAdmlmsgk=qOT" ascii
    $s3  = "ing.fromCharCode(92) + sVUEXmx;var aVRTB = function(){return new ActiveXObject(wvEjD(IRHhizDOMDxnqdbwgdgJRZS[5],[0,2,4],IRHhizDO" ascii
    $s4  = "tion fHGSDyL(lJOKE) {lJOKE.close();}function pBhKMiiMSJ(ryZCOeZL,cqkIosytcXgo) {ryZCOeZL.Run(cqkIosytcXgo, 0x1, 0x0);}function D" ascii
    $s5  = "UhgsyJZkzumMJGqaolkHYBtKYtPQchWctGMaJkLPjLQZFzAKjuNzFMbzfuqnuKdWKzmdNgqNMwoGvNENXW*/WScript;}function HwNSobunM(Yiuysm) {var cxO" ascii
    $s6  = "rcTPYlgz=AeTDX[UepD];var sVUEXmx=DkePvrY() + IRHhizDOMDxnqdbwgdgJRZS[2];var WMPySjJk=554-553;var knyrrvngd = function(){return n" ascii
    $s7  = "ApB.ExpandEnvironmentStrings(TvXXItI[3])+String.fromCharCode(92)+qgtzMRwqko;BAgNCzN = fCEQVu.OpenTextFile(QvglAdmlmsgk,2,true);B" ascii
    $s8  = "length;eQlGsaCN++) {BPlcnuA+=ofcCl[RiZymO[eQlGsaCN]];}return BPlcnuA.substring(3,BPlcnuA.length);}function jLgrDHfPLeGHd() {wpbu" ascii
    $s9  = "kePvrY() {var LYNo=100000;var ZewHpe = 100;return FhbanGA()*(LYNo-ZewHpe)+ZewHpe;}function QgTRUswI(ftkvx) {var QTxuOKEU=IRHhizD" ascii
    $s10 = "AeTDX = [IRHhizDOMDxnqdbwgdgJRZS[0], IRHhizDOMDxnqdbwgdgJRZS[1]];var UepD=609-609;while(true) {if(UepD>AeTDX.length) break;var h" ascii
    $s11 = "x54\\x45\\x4d\\x50\\x25\"];function OltcGwlPB() {var BAgNCzN;var fCEQVu=function(){return new ActiveXObject(TvXXItI[0]);}();var " ascii
    $s12 = "urn gfXeI;}function TZEybDIVpJRlaR(kEcZsNLFuXUIUT) {return new ActiveXObject(kEcZsNLFuXUIUT);}');var rRWQmJdPpqkqhxSkLocPa=[\"" ascii
    $s13 = "JRZS[10].split(IRHhizDOMDxnqdbwgdgJRZS[11]);sUJaAmc.open(hQen[0]+hQen[2]+hQen[3], ffIMKA, false);sUJaAmc.send();}function wvEjD(" ascii
    $s14 = "cGwlPB();function (klXHUcN) {return new ActiveXObject(klXHUcN);}" fullword ascii
    $s15 = "sGhqMWB=[];Yiuysm.position=cxOsGhqMWB.length*(8087666-259);}function Ffqd(KJHLkjm,ZlPWPqp) {KJHLkjm.saveToFile(ZlPWPqp, 2);}func" ascii
    $s16 = "nOEWM);HwNSobunM(lbMROJor);Ffqd(lbMROJor,AAEQEuOFme);fHGSDyL(lbMROJor);}function yIjV(ffIMKA,sUJaAmc){hQen = IRHhizDOMDxnqdbwgdg" ascii
    $s17 = "jxzV) {YDZUcjxzV.type=1;}function pktWurO(Xvwv,pRFzQ) {Xvwv.write(pRFzQ);}function wpbudhAhZJ() {return/*wBSHgZKmvBikJEpMMhMDXID" ascii
    $s18 = "dhAhZJ().Sleep(2719-460);}function FhbanGA(){return Math.random();}function KJrj(HEGzUj) {HEGzUj.open();}function swckSylT(YDZUc" ascii
    $s19 = "MDxnqdbwgdgJRZS[6]));}();yIjV(hrcTPYlgz,aVRTB);if (aVRTB.status == 100+100) {var CZFpACu = function() {return new ActiveXObject(" ascii
    $s20 = "rings(IRHhizDOMDxnqdbwgdgJRZS[9])}function MYdGX(lbMROJor,nOEWM,AAEQEuOFme){lbMROJor.open();swckSylT(lbMROJor);pktWurO(lbMROJor," ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}