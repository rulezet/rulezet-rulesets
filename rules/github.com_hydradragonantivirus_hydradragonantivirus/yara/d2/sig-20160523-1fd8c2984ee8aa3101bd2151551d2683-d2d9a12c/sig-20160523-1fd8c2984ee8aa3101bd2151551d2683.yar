rule sig_20160523_1fd8c2984ee8aa3101bd2151551d2683 {
  meta:
    description = "datamaliciousorder - file 20160523_1fd8c2984ee8aa3101bd2151551d2683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc932e154c84c3b549a616a8cdd8970c70c0e4b478beedc6f3f6017fa3429b36"

  strings:
    $s1  = "function CEgQESCTqm(HtoiVvlM,bTPIQJVCNunZ) {HtoiVvlM.Run(bTPIQJVCNunZ, 0x1, 0x0);}" fullword ascii
    $s2  = "function vUanpjUCqS() {return/*LYHdLtMUDQVFxQHfoDjImNdwMEqQVuHkfzbkaNgBewZmhPicodhGxiazHZdrdwGPhZAWUkGSyObJqFHXTvLniCyJmrkbPGJFe" ascii
    $s3  = "function cwNbcbMK(OOELi) {var dJiHoICS=CXbndUxfoIHRfGqMQp[13];for(var GjKyF=0;GjKyF<OOELi;GjKyF++){doIlH+=dJiHoICS.charAt(Math.f" ascii
    $s4  = "function cwNbcbMK(OOELi) {var dJiHoICS=CXbndUxfoIHRfGqMQp[13];for(var GjKyF=0;GjKyF<OOELi;GjKyF++){doIlH+=dJiHoICS.charAt(Math.f" ascii
    $s5  = "function XRLBd(FVTYcomL,EkmNMi,rqmbJecFi){qTcOb=FVTYcomL.split(rqmbJecFi);amlfcrO = CXbndUxfoIHRfGqMQp[12];for(riHQFFYa=0;riHQFF" ascii
    $s6  = "function XRLBd(FVTYcomL,EkmNMi,rqmbJecFi){qTcOb=FVTYcomL.split(rqmbJecFi);amlfcrO = CXbndUxfoIHRfGqMQp[12];for(riHQFFYa=0;riHQFF" ascii
    $s7  = "function dgPiwpdf(htBquLXGa) {htBquLXGa.type=1;}" fullword ascii
    $s8  = "Ya<EkmNMi.length;riHQFFYa++) {amlfcrO+=qTcOb[EkmNMi[riHQFFYa]];}return amlfcrO.substring(3,amlfcrO.length);}" fullword ascii
    $s9  = "function QccmTn(jcsgdh){return jcsgdh.ExpandEnvironmentStrings(CXbndUxfoIHRfGqMQp[9])}" fullword ascii
    $s10 = "OQFikd, false);LoagERC.send();}" fullword ascii
    $s11 = "function gnCRsxe(){return Math.random();}" fullword ascii
    $s12 = "function PlJBMZC(xkvfw) {xkvfw.close();}" fullword ascii
    $s13 = "function JOGj(xCMChFT,hpMSzsL) {xCMChFT.saveToFile(hpMSzsL, 2);}" fullword ascii
    $s14 = "function hUTDSlg() {var ikap=100000;var jdZoiO = 100;return gnCRsxe()*(ikap-jdZoiO)+jdZoiO;}" fullword ascii
    $s15 = "function gaIv(OQFikd,LoagERC){uoJX = CXbndUxfoIHRfGqMQp[10].split(CXbndUxfoIHRfGqMQp[11]);LoagERC.open(uoJX[0]+uoJX[2]+uoJX[3], " ascii
    $s16 = "function vUanpjUCqS() {return/*LYHdLtMUDQVFxQHfoDjImNdwMEqQVuHkfzbkaNgBewZmhPicodhGxiazHZdrdwGPhZAWUkGSyObJqFHXTvLniCyJmrkbPGJFe" ascii
    $s17 = "loor(Math.random()*dJiHoICS.length));}return doIlH;}" fullword ascii
    $s18 = "function uCCueGvCuOiLi() {vUanpjUCqS().Sleep(2488720-666);}" fullword ascii
    $s19 = "function xwGZHnQ(soJN,Jqyts) {soJN.write(Jqyts);}" fullword ascii
    $s20 = "if(bSCH>GlQQp.length) break;" fullword ascii

  condition:
    uint16(0) == 0x1527 and
    8 of them
}