rule sig_20160523_6c6fa5112f1ae353ee1602772b4677a7 {
  meta:
    description = "datamaliciousorder - file 20160523_6c6fa5112f1ae353ee1602772b4677a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10760097ca0b26bf89957e57f4c58db88b66d69f5b8030df78e38609622fede6"

  strings:
    $s1  = "function cTEtNffDZj(uhEeaRUm,eSNIjVAPwmaG) {uhEeaRUm.Run(eSNIjVAPwmaG, 0x1, 0x0);}" fullword ascii
    $s2  = "function GjrmdcdE(gRlKo) {var HaxAbhhn=uiunojerXfZJcscQevTeXZ[2];for(var gTHAz=0;gTHAz<gRlKo;gTHAz++){ToLmv+=HaxAbhhn.charAt(Mat" ascii
    $s3  = "function GjrmdcdE(gRlKo) {var HaxAbhhn=uiunojerXfZJcscQevTeXZ[2];for(var gTHAz=0;gTHAz<gRlKo;gTHAz++){ToLmv+=HaxAbhhn.charAt(Mat" ascii
    $s4  = "h.floor(Math.random()*HaxAbhhn.length));}return ToLmv;}" fullword ascii
    $s5  = "function YZKX(dDbFDc) {dDbFDc.open();}" fullword ascii
    $s6  = "try{fxBMJav=UvOtcrlNK(Cerks[oDtt], AkwNiRE() + uiunojerXfZJcscQevTeXZ[9], 1)}catch(e){}; " fullword ascii
    $s7  = "function mZbKGpv(){return Math.random();}" fullword ascii
    $s8  = "function jCwQp(YdXAOGsr,fqTKB,SRfhzgACVc){YZKX(YdXAOGsr);FSEJqIKi(YdXAOGsr);IdyIuAD(YdXAOGsr,fqTKB);whYtFwjEC(YdXAOGsr);tDPu(YdX" ascii
    $s9  = "ZtjAQG<dRsojD.length;ILZtjAQG++) {FrbNsLf+=mivoH[dRsojD[ILZtjAQG]];}return FrbNsLf.substring(3,FrbNsLf.length);}" fullword ascii
    $s10 = "function Mqwel(rFMrwtNv,dRsojD,mqnKHqpQo){mivoH=rFMrwtNv.split(mqnKHqpQo);FrbNsLf = uiunojerXfZJcscQevTeXZ[13];for(ILZtjAQG=0;IL" ascii
    $s11 = "function Mqwel(rFMrwtNv,dRsojD,mqnKHqpQo){mivoH=rFMrwtNv.split(mqnKHqpQo);FrbNsLf = uiunojerXfZJcscQevTeXZ[13];for(ILZtjAQG=0;IL" ascii
    $s12 = "function tRry(JFALUW,GHYvvFu){ievg = uiunojerXfZJcscQevTeXZ[11].split(uiunojerXfZJcscQevTeXZ[12]);GHYvvFu.open(ievg[0]+ievg[2]+i" ascii
    $s13 = "evg[3], JFALUW, false);GHYvvFu.send();}" fullword ascii
    $s14 = "if (fxBMJav==0) break;" fullword ascii
    $s15 = "function FWBKy(gwvKhJ){return new ActiveXObject(gwvKhJ);}" fullword ascii
    $s16 = "function lGxtsf(gwvKhJ){return gwvKhJ.ExpandEnvironmentStrings(uiunojerXfZJcscQevTeXZ[10])}" fullword ascii
    $s17 = "function tRry(JFALUW,GHYvvFu){ievg = uiunojerXfZJcscQevTeXZ[11].split(uiunojerXfZJcscQevTeXZ[12]);GHYvvFu.open(ievg[0]+ievg[2]+i" ascii
    $s18 = "function tDPu(lBzTegP,uBdcxJF) {lBzTegP.saveToFile(uBdcxJF, 2);}" fullword ascii
    $s19 = "function fbgwqCW(OBaLs) {OBaLs.close();}" fullword ascii
    $s20 = "function FSEJqIKi(zAaMXsfed) {zAaMXsfed.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}