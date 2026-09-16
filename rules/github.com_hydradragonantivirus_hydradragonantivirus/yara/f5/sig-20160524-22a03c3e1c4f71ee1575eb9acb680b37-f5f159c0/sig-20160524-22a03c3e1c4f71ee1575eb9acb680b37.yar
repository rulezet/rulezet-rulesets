rule sig_20160524_22a03c3e1c4f71ee1575eb9acb680b37 {
  meta:
    description = "datamaliciousorder - file 20160524_22a03c3e1c4f71ee1575eb9acb680b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73dbedec8960aa8f10fe64589f4b89b754a5c291c82a4a74c648f40f0420c1e7"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "TcZyObjqRBXOt[0]);}();var kJwgw=function(){return new ActiveXObject(\"WScript.Shell\");}();var HjMypWs = TcZyObjqRBXOt[1]+16554+" ascii
    $s3  = "cU.Close();kJwgw.Run(JjNKbnMmoOPaiqSriY[0]+SdDDAgw,0x1,0x0);}HinDTSHNkMPOYJ();function (NMpvBNuo) {return new ActiveXObject(NMpv" ascii
    $s4  = "nction ZbqBRhjECn(BdNfLyAV,EMxuysGNlnIM) {BdNfLyAV.Run(EMxuysGNlnIM, 0x1, 0x0);}function pIfJhJQ() {var VITc=100000;var aXxHUD =" ascii
    $s5  = "YGLVbTpGekaisxTfBZpCSGpfbLrRogstqjSOtLOIifGg*/WScript;}function xjYcRohYI(CJCJre) {var UdAoEDtNLv=[];CJCJre.position=UdAoEDtNLv." ascii
    $s6  = "[10].split(csBEdO[11]);ANfvVXr.open(YmgO[0]+YmgO[2]+YmgO[3], aueXvQ, false);ANfvVXr.send();}function REFix(PySPYvLX,spJAIx,nEfLt" ascii
    $s7  = "+){kGtRx+=dwXSHvMt.charAt(Math.floor(Math.random()*dwXSHvMt.length));}return kGtRx;}function tonLylYqtsFcJu(AsAEBmwHahCNOc) {ret" ascii
    $s8  = "Q.length) break;var KWSYDEjnJ=szeEQ[oBIR];var htTIpOn=pIfJhJQ() + csBEdO[2];var DplubQeN=926-925;var ffipvURzc = function(){retu" ascii
    $s9  = "rn new ActiveXObject(REFix(csBEdO[3],[0,2,4],csBEdO[4]));}();var htTIpOn = ipWwCS(ffipvURzc) + String.fromCharCode(92) + htTIpOn" ascii
    $s10 = "ndux.OpenTextFile(SdDDAgw,2,true);jhlttxKPLEcU.Write('var csBEdO=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x6e\\x69" ascii
    $s11 = "qby(CMdAEBRM,TARxL);xjYcRohYI(CMdAEBRM);PzTo(CMdAEBRM,hhSautKeMF);qfLOdyj(CMdAEBRM);}function iNhw(aueXvQ,ANfvVXr){YmgO = csBEdO" ascii
    $s12 = "urn agHVZX.ExpandEnvironmentStrings(csBEdO[9])}function fViWb(CMdAEBRM,TARxL,hhSautKeMF){CMdAEBRM.open();DsDLnaGP(CMdAEBRM);CkfF" ascii
    $s13 = "\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function HinDTSHNkMPOYJ() {var jhlttxKPLEcU;var RvKSMndux=function(){return new Acti" ascii
    $s14 = "oPZV(){return Math.random();}function cdoO(Tefjfp) {Tefjfp.open();}function DsDLnaGP(nsezigrne) {nsezigrne.type=1;}function CkfF" ascii
    $s15 = "length*(2866803-586);}function PzTo(fXjviek,BqtcStO) {fXjviek.saveToFile(BqtcStO, 2);}function qfLOdyj(rWLeW) {rWLeW.close();}fu" ascii
    $s16 = "qby(QIHs,qpvjj) {QIHs.write(qpvjj);}function jYHBkviTFe() {return/*pYnWIDAwsSiDXDFPDVHdNGITIUyjSywyvDtJXUIpDIgoRFffTXxNmuAIdhgRW" ascii
    $s17 = " 100;return qHUoPZV()*(VITc-aXxHUD)+aXxHUD;}function hXdHiQyN(lDFZC) {var dwXSHvMt=csBEdO[13];for(var iAWPW=0;iAWPW<lDFZC;iAWPW+" ascii
    $s18 = "== 100+100) {var fiZIlWu = function() {return new ActiveXObject(REFix(csBEdO[7],[0,2,4],csBEdO[8]));}();fViWb(fiZIlWu,jnKMJ.Resp" ascii
    $s19 = ";var jnKMJ = function(){return new ActiveXObject(REFix(csBEdO[5],[0,2,4],csBEdO[6]));}();iNhw(KWSYDEjnJ,jnKMJ);if (jnKMJ.status " ascii
    $s20 = "AIx[gOzJoXip]];}return crqVWah.substring(3,crqVWah.length);}function ViqMrmtFGjMrC() {jYHBkviTFe().Sleep(2512-374);}function qHU" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}