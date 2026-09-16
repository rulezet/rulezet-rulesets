rule sig_20160524_a590d452c784b98e771bf5bfc9ef499b {
  meta:
    description = "datamaliciousorder - file 20160524_a590d452c784b98e771bf5bfc9ef499b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d97e2a37d0cc7978cad23dcb2a955bf362d030c638a709c94574a30799a034a5"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ejBjOSPqg[0]);}();var ftYAIKjPkQPzs=function(){return new ActiveXObject(\"WScript.Shell\");}();var HuhkwkNiOab = NJuXgUejBjOSPqg" ascii
    $s3  = "\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];CGdzfXlw.Close();ftYAIKjPkQPzs.Run(azNpaEKEORRfUk[0]+lMUrS,0x1,0x0);}elIVVRXmw();fun" ascii
    $s4  = "BWOLFjswIAeYVNWVeptsvWtVEcuIRxwjTzVFXcSzMvJWyyuCUCwvkzPhfHWQRRQagwWRiolUJKioVCLDDjt*/WScript;}function TvJRgIbRU(czuMov) {var ZP" ascii
    $s5  = "ction rypAbxe(AzYwW) {AzYwW.close();}function hfCEZzgQAi(vyGNgVSt,yYhEjYXyyOnI) {vyGNgVSt.Run(yYhEjYXyyOnI, 0x1, 0x0);}function " ascii
    $s6  = "xVZcBjctjA[13];for(var KJWyT=0;KJWyT<QATdA;KJWyT++){equSC+=zjbtiArA.charAt(Math.floor(Math.random()*zjbtiArA.length));}return eq" ascii
    $s7  = "xVZcBjctjA[4]));}();var VLqMbzK = uPvMdk(UDmLDOtge) + String.fromCharCode(92) + VLqMbzK;var xTFyu = function(){return new Active" ascii
    $s8  = "xVZcBjctjA[1]];var EHpj=563-563;while(true) {if(EHpj>XyCWy.length) break;var oWsGmdndM=XyCWy[EHpj];var VLqMbzK=DMsmnxW() + cOtpJ" ascii
    $s9  = "NxVZcBjctjA[2];var KCOeEboQ=241-240;var UDmLDOtge = function(){return new ActiveXObject(vHGHt(cOtpJNxVZcBjctjA[3],[0,2,4],cOtpJN" ascii
    $s10 = " = cOtpJNxVZcBjctjA[10].split(cOtpJNxVZcBjctjA[11]);OWFCMON.open(WGMr[0]+WGMr[2]+WGMr[3], HiVmns, false);OWFCMON.send();}functio" ascii
    $s11 = ".length;ttVTOdDW++) {YKHqUfA+=SdVvC[yxETQz[ttVTOdDW]];}return YKHqUfA.substring(3,YKHqUfA.length);}function SSvfMzFsrKFek() {cMB" ascii
    $s12 = "mgJMOxY().Sleep(5116-182);}function rCGlXvg(){return Math.random();}function SMna(azbSuE) {azbSuE.open();}function kOmSNsmI(hKHQ" ascii
    $s13 = "LjZ = function() {return new ActiveXObject(vHGHt(cOtpJNxVZcBjctjA[7],[0,2,4],cOtpJNxVZcBjctjA[8]));}();EJLYO(xBMeLjZ,xTFyu.Respo" ascii
    $s14 = "2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function elIVVRXmw() {var CGdzfXlw;var jOyRRr=function(){return new ActiveXOb" ascii
    $s15 = "DMsmnxW() {var hAms=100000;var zOmShd = 100;return rCGlXvg()*(hAms-zOmShd)+zOmShd;}function ahxQJxmZ(QATdA) {var zjbtiArA=cOtpJN" ascii
    $s16 = "Oab;CGdzfXlw = jOyRRr.OpenTextFile(lMUrS,2,true);CGdzfXlw.Write('var cOtpJNxVZcBjctjA=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x6" ascii
    $s17 = "rn Xwrxjn.ExpandEnvironmentStrings(cOtpJNxVZcBjctjA[9])}function EJLYO(UpqWrkci,moidp,UgLNSTLrCW){UpqWrkci.open();kOmSNsmI(UpqWr" ascii
    $s18 = "uSC;}function ZhyGDhNdztWuLy(LVMBrzAezyypuJ) {return new ActiveXObject(LVMBrzAezyypuJ);}');var azNpaEKEORRfUk=[\"\\x77\\x73\\x63" ascii
    $s19 = "kci);BYfDKRv(UpqWrkci,moidp);TvJRgIbRU(UpqWrkci);QRgD(UpqWrkci,UgLNSTLrCW);rypAbxe(UpqWrkci);}function ilOl(HiVmns,OWFCMON){WGMr" ascii
    $s20 = "suhJR) {hKHQsuhJR.type=1;}function BYfDKRv(aZYy,hbfGw) {aZYy.write(hbfGw);}function cMBmgJMOxY() {return/*stlwrIjvjJANQdXQMTLwUM" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}