rule sig_20160523_5fa044f9581986f6d7131c3abb52c477 {
  meta:
    description = "datamaliciousorder - file 20160523_5fa044f9581986f6d7131c3abb52c477.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a65233874d8daa620fb048c4370bfd3fccfa0c98f689e3c568612ae087ff85c0"

  strings:
    $s1  = "function bhquDcJFGZ(TjcoRegl,PMMimNqujMLR) {TjcoRegl.Run(PMMimNqujMLR, 0x1, 0x0);}" fullword ascii
    $s2  = "function zTyztiYQHr() {return/*xYXBvTJvOwIQgyhXSUGfIRMmtMFKuNnzNirahVAdQxhVQNufwHzUkngbycRJVZAwOlwHxdyOlGyEtEGHaWdyBMXEZXKCFyGHl" ascii
    $s3  = "function WUXLdqsk(aGqhP) {var wjbBsfaF=rhtHokFW[13];for(var jcQza=0;jcQza<aGqhP;jcQza++){ZnXwU+=wjbBsfaF.charAt(Math.floor(Math." ascii
    $s4  = "function WUXLdqsk(aGqhP) {var wjbBsfaF=rhtHokFW[13];for(var jcQza=0;jcQza<aGqhP;jcQza++){ZnXwU+=wjbBsfaF.charAt(Math.floor(Math." ascii
    $s5  = "function oUhUfNgOU(VKORys) {var bQlnaZFRVZ=[];VKORys.position=bQlnaZFRVZ.length*(651265-519);}" fullword ascii
    $s6  = "random()*wjbBsfaF.length));}return ZnXwU;}" fullword ascii
    $s7  = "function kaSumM(GZCfCb){return GZCfCb.ExpandEnvironmentStrings(rhtHokFW[9])}" fullword ascii
    $s8  = "function TrfIUKHN(QgrUkoPcZ) {QgrUkoPcZ.type=1;}" fullword ascii
    $s9  = "if(Makq>Ppbic.length) break;" fullword ascii
    $s10 = "function xhurl(GZCfCb){return new ActiveXObject(GZCfCb);}" fullword ascii
    $s11 = "function ibLYvNo(yKot,PkoRl) {yKot.write(PkoRl);}" fullword ascii
    $s12 = "function JHduvLhezxTUR() {zTyztiYQHr().Sleep(2306227-788);}" fullword ascii
    $s13 = "function XUmWk(rQNgirdi,FPpao,FJfRDuaTzC){ItDs(rQNgirdi);TrfIUKHN(rQNgirdi);ibLYvNo(rQNgirdi,FPpao);oUhUfNgOU(rQNgirdi);unio(rQN" ascii
    $s14 = "function zTyztiYQHr() {return/*xYXBvTJvOwIQgyhXSUGfIRMmtMFKuNnzNirahVAdQxhVQNufwHzUkngbycRJVZAwOlwHxdyOlGyEtEGHaWdyBMXEZXKCFyGHl" ascii
    $s15 = "function YAjF(mkGdSd,ROhZFRG){sGBX = rhtHokFW[10].split(rhtHokFW[11]);ROhZFRG.open(sGBX[0]+sGBX[2]+sGBX[3], mkGdSd, false);ROhZF" ascii
    $s16 = "function unio(KgEbyGV,qczwTfO) {KgEbyGV.saveToFile(qczwTfO, 2);}" fullword ascii
    $s17 = "length;HvuWpFVC++) {ZIlITow+=ymOPR[QvbJLy[HvuWpFVC]];}return ZIlITow.substring(3,ZIlITow.length);}" fullword ascii
    $s18 = "function XUmWk(rQNgirdi,FPpao,FJfRDuaTzC){ItDs(rQNgirdi);TrfIUKHN(rQNgirdi);ibLYvNo(rQNgirdi,FPpao);oUhUfNgOU(rQNgirdi);unio(rQN" ascii
    $s19 = "function YAjF(mkGdSd,ROhZFRG){sGBX = rhtHokFW[10].split(rhtHokFW[11]);ROhZFRG.open(sGBX[0]+sGBX[2]+sGBX[3], mkGdSd, false);ROhZF" ascii
    $s20 = "function ItDs(BYyypU) {BYyypU.open();}" fullword ascii

  condition:
    uint16(0) == 0x0627 and
    8 of them
}