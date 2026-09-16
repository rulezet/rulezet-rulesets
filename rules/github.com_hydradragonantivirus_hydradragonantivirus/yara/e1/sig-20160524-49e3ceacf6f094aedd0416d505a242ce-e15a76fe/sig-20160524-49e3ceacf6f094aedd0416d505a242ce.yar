rule sig_20160524_49e3ceacf6f094aedd0416d505a242ce {
  meta:
    description = "datamaliciousorder - file 20160524_49e3ceacf6f094aedd0416d505a242ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d08158f7ada017f94985b9f1249d90ac12c04762dbcf89ea134a29559c520b4"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "){return new ActiveXObject(EaqGJbKVucPwxgnoQdp[0]);}();var TZJojMZeBuGZb=function(){return new ActiveXObject(\"WScript.Shell\");" ascii
    $s3  = ";var ElUyAvcbd=Hhajt[Gopg];var VUZnqiM=WZGaxfr() + ozduzgkyiYdNJHQeHRqs[2];var CMdfUNrw=949-948;var NyjCgyrQy = function(){retur" ascii
    $s4  = "65\\x20\"];GAmNVkrIOMliC.Close();TZJojMZeBuGZb.Run(iFINjwyOluNO[0]+IhYXCBynTVP,0x1,0x0);}TtIiZiieQ();function (cWHesXBCqp) {retu" ascii
    $s5  = "TAQRwVHigwaEJvvlpJQGLGJUibZIqokZwlozliKlVYxQjaXspelwXCK*/WScript;}function ewrXgJCOp(jypkJz) {var XVtwMcZHfJ=[];jypkJz.position=" ascii
    $s6  = "mhZe=0;ImhZe<VwSQP;ImhZe++){MEDxV+=quyxZDEY.charAt(Math.floor(Math.random()*quyxZDEY.length));}return MEDxV;}function lVPrAKeHms" ascii
    $s7  = ".fromCharCode(92) + VUZnqiM;var xyKKM = function(){return new ActiveXObject(enchG(ozduzgkyiYdNJHQeHRqs[5],[0,2,4],ozduzgkyiYdNJH" ascii
    $s8  = "n new ActiveXObject(enchG(ozduzgkyiYdNJHQeHRqs[3],[0,2,4],ozduzgkyiYdNJHQeHRqs[4]));}();var VUZnqiM = btXAiL(NyjCgyrQy) + String" ascii
    $s9  = "XVtwMcZHfJ.length*(3231937-304);}function NZcw(sOascSZ,dBFvIbR) {sOascSZ.saveToFile(dBFvIbR, 2);}function oMnUcux(HKjpu) {HKjpu." ascii
    $s10 = "close();}function JmbbYitTca(CNTuocVv,NDhILJbltlBK) {CNTuocVv.Run(NDhILJbltlBK, 0x1, 0x0);}function WZGaxfr() {var tHXa=100000;v" ascii
    $s11 = "uwwz(wdAkwsydeJNjHT) {return new ActiveXObject(wdAkwsydeJNjHT);}');var iFINjwyOluNO=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e" ascii
    $s12 = "79\\x77\\x73\\x5a\\x76\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function TtIiZiieQ() {var GAmNVkrIOMliC;var igP" ascii
    $s13 = "rTpGz();var Hhajt = [ozduzgkyiYdNJHQeHRqs[0], ozduzgkyiYdNJHQeHRqs[1]];var Gopg=397-397;while(true) {if(Gopg>Hhajt.length) break" ascii
    $s14 = "ar RZFUky = 100;return PtgThwV()*(tHXa-RZFUky)+RZFUky;}function JKSBmHGi(VwSQP) {var quyxZDEY=ozduzgkyiYdNJHQeHRqs[13];for(var I" ascii
    $s15 = "kyiYdNJHQeHRqs[11]);sBuvVXL.open(JbGe[0]+JbGe[2]+JbGe[3], ZHAuBy, false);sBuvVXL.send();}function enchG(APchBsEh,wVHDQk,AUOxdfUs" ascii
    $s16 = "(EaqGJbKVucPwxgnoQdp[3])+String.fromCharCode(92)+TOxetfzflaHHY;GAmNVkrIOMliC = igPpuOHMUSW.OpenTextFile(IhYXCBynTVP,2,true);GAmN" ascii
    $s17 = "QeHRqs[6]));}();lkbd(ElUyAvcbd,xyKKM);if (xyKKM.status == 100+100) {var sCFvdMF = function() {return new ActiveXObject(enchG(ozd" ascii
    $s18 = "nction RkFHpDo(vAsp,ZdlcS) {vAsp.write(ZdlcS);}function yBgjjxOnnr() {return/*YbWbHeTSpBrJUXcRTwjjmEAbxzlnyMbjNwjIpiscDbQiAGmtFb" ascii
    $s19 = "CSWHdiq);NZcw(xCSWHdiq,RMdfoxgWdD);oMnUcux(xCSWHdiq);}function lkbd(ZHAuBy,sBuvVXL){JbGe = ozduzgkyiYdNJHQeHRqs[10].split(ozduzg" ascii
    $s20 = "YdNJHQeHRqs[9])}function fFadl(xCSWHdiq,wtYaA,RMdfoxgWdD){xCSWHdiq.open();DjJkQCKS(xCSWHdiq);RkFHpDo(xCSWHdiq,wtYaA);ewrXgJCOp(x" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}