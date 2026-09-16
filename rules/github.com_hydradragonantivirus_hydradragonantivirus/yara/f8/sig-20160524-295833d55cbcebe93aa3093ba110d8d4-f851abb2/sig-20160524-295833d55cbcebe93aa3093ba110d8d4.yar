rule sig_20160524_295833d55cbcebe93aa3093ba110d8d4 {
  meta:
    description = "datamaliciousorder - file 20160524_295833d55cbcebe93aa3093ba110d8d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e70ee108eff2c1d0ac5a73dc1c397acf690e0f6ad8af7aae65ecdc99778b917"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "];for(var ftptD=0;ftptD<iENSZ;ftptD++){vehPJ+=ehUHjLLm.charAt(Math.floor(Math.random()*ehUHjLLm.length));}return vehPJ;}function" ascii
    $s3  = "Object(aWsZnbyfQcEzGFAcnkgyw[0]);}();var EErCgWgvmjvKwf=function(){return new ActiveXObject(\"WScript.Shell\");}();var wCrGgeEEB" ascii
    $s4  = "(OLujk) {OLujk.close();}function IOvclddJTs(sVFmZfSR,kfEKLnpYNuXj) {sVFmZfSR.Run(kfEKLnpYNuXj, 0x1, 0x0);}function YViGJEF() {va" ascii
    $s5  = "74\\x2e\\x65\\x78\\x65\\x20\"];razRaQNBO.Close();EErCgWgvmjvKwf.Run(OFIFlFTomyEBXrRFo[0]+irzBxMSkEjc,0x1,0x0);}QZhsAHU();functio" ascii
    $s6  = "UREujpaEONlDaKrDMdUpprcYCyrqQYUDWNqvorIeIICpxkdoyWQMeqTVgqSzWvRLsDvpMn*/WScript;}function SVwTveCUi(rXWJtZ) {var vfxCsZmVjw=[];r" ascii
    $s7  = "];var sDvV=181-181;while(true) {if(sDvV>aowPe.length) break;var HnyHdejly=aowPe[sDvV];var ouPQwRK=YViGJEF() + pxGpDASxhqupxjlB[2" ascii
    $s8  = "));}();var ouPQwRK = RcgLxV(GlnstlRcw) + String.fromCharCode(92) + ouPQwRK;var owfcm = function(){return new ActiveXObject(pNxoV" ascii
    $s9  = "nGv++) {eJyxYYo+=sTYyH[XEaZyW[aIVYgnGv]];}return eJyxYYo.substring(3,eJyxYYo.length);}function JxWwnVnEkTEIf() {aSazLAwxFJ().Sle" ascii
    $s10 = "mbwo.type=1;}function lfJSWia(Eyvn,wvEPT) {Eyvn.write(wvEPT);}function aSazLAwxFJ() {return/*KiTlOlnxhMXnMoKXdXLtdsLUmEVrAkbcuro" ascii
    $s11 = "XWJtZ.position=vfxCsZmVjw.length*(1559847-215);}function YYUc(ucWVKZp,HFhwqrr) {ucWVKZp.saveToFile(HFhwqrr, 2);}function qAGWwrI" ascii
    $s12 = "andEnvironmentStrings(pxGpDASxhqupxjlB[9])}function sUeKo(MsnSMiHk,hqSUH,jrbyFdkrVA){MsnSMiHk.open();JjanqDxq(MsnSMiHk);lfJSWia(" ascii
    $s13 = "r yvdR=100000;var YEveXk = 100;return mbMGjmo()*(yvdR-YEveXk)+YEveXk;}function ldNLGZmg(iENSZ) {var ehUHjLLm=pxGpDASxhqupxjlB[13" ascii
    $s14 = "MsnSMiHk,hqSUH);SVwTveCUi(MsnSMiHk);YYUc(MsnSMiHk,jrbyFdkrVA);qAGWwrI(MsnSMiHk);}function zyYH(BFgWtV,jrGiBru){CZUm = pxGpDASxhq" ascii
    $s15 = "x72\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function QZhsAHU() {var razRaQNBO;var UqKtNLalgPZP=function(){retu" ascii
    $s16 = "upxjlB[10].split(pxGpDASxhqupxjlB[11]);jrGiBru.open(CZUm[0]+CZUm[2]+CZUm[3], BFgWtV, false);jrGiBru.send();}function pNxoV(XQcRY" ascii
    $s17 = "n() {return new ActiveXObject(pNxoV(pxGpDASxhqupxjlB[7],[0,2,4],pxGpDASxhqupxjlB[8]));}();sUeKo(onwgmRL,owfcm.ResponseBody,ouPQw" ascii
    $s18 = "zGFAcnkgyw[3])+String.fromCharCode(92)+wCrGgeEEBwUYp;razRaQNBO = UqKtNLalgPZP.OpenTextFile(irzBxMSkEjc,2,true);razRaQNBO.Write('" ascii
    $s19 = "XKXeq) {return new ActiveXObject(PwqXKXeq);}" fullword ascii
    $s20 = "];var CIMOIDPu=657-656;var GlnstlRcw = function(){return new ActiveXObject(pNxoV(pxGpDASxhqupxjlB[3],[0,2,4],pxGpDASxhqupxjlB[4]" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}