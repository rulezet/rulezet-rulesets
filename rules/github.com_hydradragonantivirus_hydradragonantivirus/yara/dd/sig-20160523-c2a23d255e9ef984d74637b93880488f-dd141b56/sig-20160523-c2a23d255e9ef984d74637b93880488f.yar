rule sig_20160523_c2a23d255e9ef984d74637b93880488f {
  meta:
    description = "datamaliciousorder - file 20160523_c2a23d255e9ef984d74637b93880488f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93f5a2e5cf74d9b9f7b240d73304ded915252c16e098e814677f221bf4d94da3"

  strings:
    $s1  = "function wMcZHfJNZc(wsOascSZ,dBFvIbRoMnUc) {wsOascSZ.Run(dBFvIbRoMnUc, 0x1, 0x0);}" fullword ascii
    $s2  = "function nakTTvOZ(rDMxF) {var dPHhajtW=UOyXNLyqRmzmJdknfnY[13];for(var ZGaxf=0;ZGaxf<rDMxF;ZGaxf++){rtHXa+=dPHhajtW.charAt(Math." ascii
    $s3  = "function nakTTvOZ(rDMxF) {var dPHhajtW=UOyXNLyqRmzmJdknfnY[13];for(var ZGaxf=0;ZGaxf<rDMxF;ZGaxf++){rtHXa+=dPHhajtW.charAt(Math." ascii
    $s4  = ", Laudsf, false);FadlxCS.send();}" fullword ascii
    $s5  = "function AuBys(BuvVXLJb,GeZbaD,DOdOgFpQU){Bench=BuvVXLJb.split(DOdOgFpQU);GAPchBs = UOyXNLyqRmzmJdknfnY[12];for(sHnDuEkt=0;sHnDu" ascii
    $s6  = "function LQFV(Laudsf,FadlxCS){WHdi = UOyXNLyqRmzmJdknfnY[10].split(UOyXNLyqRmzmJdknfnY[11]);FadlxCS.open(WHdi[0]+WHdi[2]+WHdi[3]" ascii
    $s7  = "function VHDQkAU(){return Math.random();}" fullword ascii
    $s8  = "function DlpZiE(geMzlH){return geMzlH.ExpandEnvironmentStrings(UOyXNLyqRmzmJdknfnY[9])}" fullword ascii
    $s9  = "floor(Math.random()*dPHhajtW.length));}return rtHXa;}" fullword ascii
    $s10 = "function PsFWLpV() {var hQkF=100000;var SUboPp = 100;return VHDQkAU()*(hQkF-SUboPp)+SUboPp;}" fullword ascii
    $s11 = "Ekt<GeZbaD.length;sHnDuEkt++) {GAPchBs+=Bench[GeZbaD[sHnDuEkt]];}return GAPchBs.substring(3,GAPchBs.length);}" fullword ascii
    $s12 = "function gdLae(geMzlH){return new ActiveXObject(geMzlH);}" fullword ascii
    $s13 = "function eAzDMhHP(wCsEBhJgT) {wCsEBhJgT.type=1;}" fullword ascii
    $s14 = "function AuBys(BuvVXLJb,GeZbaD,DOdOgFpQU){Bench=BuvVXLJb.split(DOdOgFpQU);GAPchBs = UOyXNLyqRmzmJdknfnY[12];for(sHnDuEkt=0;sHnDu" ascii
    $s15 = "function LQFV(Laudsf,FadlxCS){WHdi = UOyXNLyqRmzmJdknfnY[10].split(UOyXNLyqRmzmJdknfnY[11]);FadlxCS.open(WHdi[0]+WHdi[2]+WHdi[3]" ascii
    $s16 = "function MjxzA(FwTGopgc,QNEnp,dfkqUbtXAi){Oxdf(FwTGopgc);eAzDMhHP(FwTGopgc);WmiPtgT(FwTGopgc,QNEnp);QeXKDjJkQ(FwTGopgc);pDov(FwT" ascii
    $s17 = "function WmiPtgT(hwVb,nFKQa) {hwVb.write(nFKQa);}" fullword ascii
    $s18 = "function QeXKDjJkQ(CKSbpl) {var zjbZxLRkFH=[];CKSbpl.position=zjbZxLRkFH.length*(2566133-307);}" fullword ascii
    $s19 = "function pDov(AspZdlc,SewrXgJ) {AspZdlc.saveToFile(SewrXgJ, 2);}" fullword ascii
    $s20 = "function COpjypk(JzXVt) {JzXVt.close();}" fullword ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}