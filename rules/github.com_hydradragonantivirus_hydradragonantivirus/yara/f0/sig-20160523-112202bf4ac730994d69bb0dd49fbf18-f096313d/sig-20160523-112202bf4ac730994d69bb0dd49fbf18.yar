rule sig_20160523_112202bf4ac730994d69bb0dd49fbf18 {
  meta:
    description = "datamaliciousorder - file 20160523_112202bf4ac730994d69bb0dd49fbf18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15f6f51b33d8f5cc46cf235674b3a4d77b783596bb2b50111110ea2dcd1d1e38"

  strings:
    $s1  = "function ebrRquAedO() {return/*erQZilfBXAYLTScsJKOzhfjJsZfnrOMMEzXjxOVttGvUhuKOKKfSGahBDxxYeFtHQQtfNMiPwRNZFrkFGBwYJNRhvgViYeLBU" ascii
    $s2  = "function jFZxaeBYuX(UDzZPOpP,gluLXXCrHcAW) {UDzZPOpP.Run(gluLXXCrHcAW, 0x1, 0x0);}" fullword ascii
    $s3  = "function orHOSWjh(ZqsMF) {var igqamLWf=RlMBzzcxTqHIQUBWCAtnC[13];for(var kythi=0;kythi<ZqsMF;kythi++){jjJjP+=igqamLWf.charAt(Mat" ascii
    $s4  = "function orHOSWjh(ZqsMF) {var igqamLWf=RlMBzzcxTqHIQUBWCAtnC[13];for(var kythi=0;kythi<ZqsMF;kythi++){jjJjP+=igqamLWf.charAt(Mat" ascii
    $s5  = "function Wbcwubp(vJwTl) {vJwTl.close();}" fullword ascii
    $s6  = "function WsXqZ(wLswoNgE,RYZPc,fQuIVuxKyY){sazL(wLswoNgE);QHsemEkR(wLswoNgE);LxrzhLr(wLswoNgE,RYZPc);ImgNkAkDM(wLswoNgE);urTo(wLs" ascii
    $s7  = "function RzULiyZ() {var GkmT=100000;var TltgCj = 100;return kzhjHqr()*(GkmT-TltgCj)+TltgCj;}" fullword ascii
    $s8  = "function WsXqZ(wLswoNgE,RYZPc,fQuIVuxKyY){sazL(wLswoNgE);QHsemEkR(wLswoNgE);LxrzhLr(wLswoNgE,RYZPc);ImgNkAkDM(wLswoNgE);urTo(wLs" ascii
    $s9  = "function kzhjHqr(){return Math.random();}" fullword ascii
    $s10 = "function ImgNkAkDM(WZtSSY) {var BJNsmAymOy=[];WZtSSY.position=BJNsmAymOy.length*(9813352-560);}" fullword ascii
    $s11 = "function LxrzhLr(iflM,Rqdkq) {iflM.write(Rqdkq);}" fullword ascii
    $s12 = "function urTo(kSJAxML,ZYYJuXT) {kSJAxML.saveToFile(ZYYJuXT, 2);}" fullword ascii
    $s13 = "function QyMze(vJcrZd){return new ActiveXObject(vJcrZd);}" fullword ascii
    $s14 = "function sazL(EfoNbg) {EfoNbg.open();}" fullword ascii
    $s15 = "function ebrRquAedO() {return/*erQZilfBXAYLTScsJKOzhfjJsZfnrOMMEzXjxOVttGvUhuKOKKfSGahBDxxYeFtHQQtfNMiPwRNZFrkFGBwYJNRhvgViYeLBU" ascii
    $s16 = "if(Bufg>cnuiF.length) break;" fullword ascii
    $s17 = "ImqTX<sNDWFA.length;edYImqTX++) {iNDtYrE+=RkrQt[sNDWFA[edYImqTX]];}return iNDtYrE.substring(3,iNDtYrE.length);}" fullword ascii
    $s18 = "function oMdsJLCGRXxIC() {ebrRquAedO().Sleep(2312532-935);}" fullword ascii
    $s19 = "function QHsemEkR(COXFopQZs) {COXFopQZs.type=1;}" fullword ascii
    $s20 = "h.floor(Math.random()*igqamLWf.length));}return jjJjP;}" fullword ascii

  condition:
    uint16(0) == 0x0527 and
    8 of them
}