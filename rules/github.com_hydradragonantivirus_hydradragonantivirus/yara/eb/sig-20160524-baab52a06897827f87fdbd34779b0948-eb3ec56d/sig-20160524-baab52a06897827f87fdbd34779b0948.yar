rule sig_20160524_baab52a06897827f87fdbd34779b0948 {
  meta:
    description = "datamaliciousorder - file 20160524_baab52a06897827f87fdbd34779b0948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a96e7ef0d72a8f36271aab86482cd7c3ca6974fbbd72cd5dcd989efdcd444977"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "KvKMthUGDwAMvyrbyZNYRlFBgTmkviyVqPIiUbIVOBQGbDXnnRwqCCdMAvmalJOepdax*/WScript;}function aGFhcFDRa(uEpBMZ) {var XJSHQcwTqM=[];uEp" ascii
    $s3  = "CrNb) {NCrNb.close();}function iXCzilzyZm(QQGGnTCx,bzLpRZFpVmia) {QQGGnTCx.Run(bzLpRZFpVmia, 0x1, 0x0);}function MbjhhXi() {var " ascii
    $s4  = "70\\x74\\x2e\\x65\\x78\\x65\\x20\"];AFIxWPbLvdz.Close();vLMdiOsFsXrHsR.Run(ULeBNeNWsClfldX[0]+TvZhQ,0x1,0x0);}hkiGrIZBR();functi" ascii
    $s5  = "waD[13];for(var ctCFP=0;ctCFP<Xhjez;ctCFP++){OAfei+=JJcHDgCy.charAt(Math.floor(Math.random()*JJcHDgCy.length));}return OAfei;}fu" ascii
    $s6  = "BMZ.position=XJSHQcwTqM.length*(9861038-432);}function MCxr(wYIWPbX,hzbNcOS) {wYIWPbX.saveToFile(hzbNcOS, 2);}function dlsPrPx(N" ascii
    $s7  = "LqkuruIYmwaD[9])}function iSPEq(mJDUCRgY,Zfnho,RvAISCIRBj){mJDUCRgY.open();HxsClqEy(mJDUCRgY);WhVXgZe(mJDUCRgY,Zfnho);aGFhcFDRa(" ascii
    $s8  = "fchBMpV=MbjhhXi() + CAOzVOCxpLkILqkuruIYmwaD[2];var WlMFyffD=433-432;var FzFHoYYka = function(){return new ActiveXObject(sCaLh(C" ascii
    $s9  = "nction mtUtRHvXYFAqES(VRjzQsKeXkGNBl) {return new ActiveXObject(VRjzQsKeXkGNBl);}');var ULeBNeNWsClfldX=[\"\\x77\\x73\\x63\\x72" ascii
    $s10 = "L++) {XxMHeoi+=XnXTi[jBblJi[arCVDWCL]];}return XxMHeoi.substring(3,XxMHeoi.length);}function POQcrBAtbBWtv() {YDUBlRMyvs().Sleep" ascii
    $s11 = "WPbLvdz;var gdRRRqvuEEgz=function(){return new ActiveXObject(YbHhgCfnlZLDnOTNYdm[0]);}();var vLMdiOsFsXrHsR=function(){return ne" ascii
    $s12 = "(5095-622);}function zQDpCXE(){return Math.random();}function vJmw(MNHJYe) {MNHJYe.open();}function HxsClqEy(PsVJukaCx) {PsVJuka" ascii
    $s13 = "OHkgu) {return new ActiveXObject(QVNOHkgu);}" fullword ascii
    $s14 = "4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x4c\\x79\\x58\\x73\\x6e\\x6a\\x44\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];fu" ascii
    $s15 = "Cx.type=1;}function WhVXgZe(rUPX,FQoSl) {rUPX.write(FQoSl);}function YDUBlRMyvs() {return/*jWLajyUfklhAmMkDLinfIccyzzPBkfkFmZACF" ascii
    $s16 = "FouK=100000;var xGzZCi = 100;return zQDpCXE()*(FouK-xGzZCi)+xGzZCi;}function PNlsvmqj(Xhjez) {var JJcHDgCy=CAOzVOCxpLkILqkuruIYm" ascii
    $s17 = "IYmwaD[0], CAOzVOCxpLkILqkuruIYmwaD[1]];var SMCs=736-736;while(true) {if(SMCs>DhdbN.length) break;var RtOAKiOxn=DhdbN[SMCs];var " ascii
    $s18 = ",true);AFIxWPbLvdz.Write('var CAOzVOCxpLkILqkuruIYmwaD=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70\\x2e\\x76\\x69" ascii
    $s19 = "AOzVOCxpLkILqkuruIYmwaD[11]);ubBrekb.open(NHJt[0]+NHJt[2]+NHJt[3], kWKjoP, false);ubBrekb.send();}function sCaLh(xvDZYjus,jBblJi" ascii
    $s20 = ";}();KaKl(RtOAKiOxn,AApTq);if (AApTq.status == 100+100) {var bJPQwmu = function() {return new ActiveXObject(sCaLh(CAOzVOCxpLkILq" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}