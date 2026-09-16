rule sig_20160524_ce5870ed871cb5e044119d011b0af2fb {
  meta:
    description = "datamaliciousorder - file 20160524_ce5870ed871cb5e044119d011b0af2fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8128c758ae8dc0abb7f154a35bb6bfc15b310fd0c6d993a11181b7332600f0a8"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "BtK.Run(teDqsmYKnlvR, 0x1, 0x0);}function pEyaXsK() {var OZWn=100000;var IMPnTb = 100;return wRPVzez()*(OZWn-IMPnTb)+IMPnTb;}fun" ascii
    $s3  = "pem=function(){return new ActiveXObject(ahYFaDcuzIygjYoE[0]);}();var fYINE=function(){return new ActiveXObject(\"WScript.Shell\"" ascii
    $s4  = "WScript;}function gRGassQmw(HuRrne) {var hzrfaVwiNc=[];HuRrne.position=hzrfaVwiNc.length*(491922-307);}function JznT(HPRSwpr,XGM" ascii
    $s5  = ",QzWpEyoXCEqYPxSUiCGg[4]));}();var ZkZxQEK = ISHvrI(tYvQVyUUl) + String.fromCharCode(92) + ZkZxQEK;var sLEoq = function(){return" ascii
    $s6  = "YPxSUiCGg[1]];var pGeE=206-206;while(true) {if(pGeE>vhIbG.length) break;var eGwyLVrQC=vhIbG[pGeE];var ZkZxQEK=pEyaXsK() + QzWpEy" ascii
    $s7  = "ring.fromCharCode(92)+KhbDV;unQjAeKwCMm = ubohRPpem.OpenTextFile(xpGdywf,2,true);unQjAeKwCMm.Write('var QzWpEyoXCEqYPxSUiCGg=[\"" ascii
    $s8  = "FJul.length);}function LsXAOacfFGYMj() {LNnjPcsLfR().Sleep(3442-920);}function wRPVzez(){return Math.random();}function IdNv(dwI" ascii
    $s9  = "oor(Math.random()*fQgJmwrc.length));}return PxXCz;}function zPMPDlZbVlNvsO(GHotJYzXAdsamk) {return new ActiveXObject(GHotJYzXAds" ascii
    $s10 = "AJo) {dwIAJo.open();}function hoGQcHyO(MgrtcHOqp) {MgrtcHOqp.type=1;}function KWSsotJ(DPjb,OnYFp) {DPjb.write(OnYFp);}function L" ascii
    $s11 = ");}qbUsP();function (meOUeXIhRm) {return new ActiveXObject(meOUeXIhRm);}" fullword ascii
    $s12 = "oXCEqYPxSUiCGg[2];var MSFjneSh=411-410;var tYvQVyUUl = function(){return new ActiveXObject(CIlmX(QzWpEyoXCEqYPxSUiCGg[3],[0,2,4]" ascii
    $s13 = "x6d\\x7a\\x55\\x63\\x79\\x50\\x63\\x68\\x54\\x6e\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function qbUsP() {var" ascii
    $s14 = "PxSUiCGg[12];for(qVqLVHNQ=0;qVqLVHNQ<fRWDVX.length;qVqLVHNQ++) {QYFFJul+=spOTy[fRWDVX[qVqLVHNQ]];}return QYFFJul.substring(3,QYF" ascii
    $s15 = " 100+100) {var CmLOtQh = function() {return new ActiveXObject(CIlmX(QzWpEyoXCEqYPxSUiCGg[7],[0,2,4],QzWpEyoXCEqYPxSUiCGg[8]));}(" ascii
    $s16 = "gGqp) {HPRSwpr.saveToFile(XGMgGqp, 2);}function aTgLtif(lbwUB) {lbwUB.close();}function qjCRgsJTMx(uTcunBtK,teDqsmYKnlvR) {uTcun" ascii
    $s17 = "unction ISHvrI(hjTUlI){return hjTUlI.ExpandEnvironmentStrings(QzWpEyoXCEqYPxSUiCGg[9])}function iGumH(rQXpnKnG,AqZDJ,ryESZEJGaI)" ascii
    $s18 = " wQzDAX, false);UDCdBVY.send();}function CIlmX(kqQoSQpS,fRWDVX,vMNnZkFsr){spOTy=kqQoSQpS.split(vMNnZkFsr);QYFFJul = QzWpEyoXCEqY" ascii
    $s19 = ");iGumH(CmLOtQh,sLEoq.ResponseBody,ZkZxQEK);}if (MSFjneSh > 0){try {qjCRgsJTMx(tYvQVyUUl,ZkZxQEK);} catch(e) {}break;};pGeE++;}f" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}