rule sig_20160520_6aec774d15f43fa0f31704b101337b99 {
  meta:
    description = "datamaliciousorder - file 20160520_6aec774d15f43fa0f31704b101337b99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e8338716b371b62df78501efb2ae78e96546a6098bea477ff74783dfbe8bac"

  strings:
    $s1  = "function EPDAXpoq(CRbaT) {var BbwTVbXc=GXtyXczKReacUsmLFA[2];for(var hlurO=0;hlurO<CRbaT;hlurO++){rgkVF+=BbwTVbXc.charAt(Math.fl" ascii
    $s2  = "function EPDAXpoq(CRbaT) {var BbwTVbXc=GXtyXczKReacUsmLFA[2];for(var hlurO=0;hlurO<CRbaT;hlurO++){rgkVF+=BbwTVbXc.charAt(Math.fl" ascii
    $s3  = "function xNNrWQc() {var cDma=100000;var VMALjo = 100;return Math.random()*(cDma-VMALjo)+VMALjo;}" fullword ascii
    $s4  = "oor(Math.random()*BbwTVbXc.length));}return rgkVF;}" fullword ascii
    $s5  = "try{AUTPTyF=mfDURDPTd(bqgBd[TAwh], xNNrWQc() + GXtyXczKReacUsmLFA[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function MTuT(rhVxyf,aQesvrJ){ZqSk = GXtyXczKReacUsmLFA[11].split(GXtyXczKReacUsmLFA[12]);aQesvrJ.open(ZqSk[0]+ZqSk[2]+ZqSk[3], " ascii
    $s7  = "rhVxyf, false);aQesvrJ.send();}" fullword ascii
    $s8  = "function bCByc(EhcQipbP,tlmXP,GbOCLnlkmn){EhcQipbP.open();EhcQipbP.type = 1;EhcQipbP.write(tlmXP);EhcQipbP.position = 0;EhcQipbP" ascii
    $s9  = "function bCByc(EhcQipbP,tlmXP,GbOCLnlkmn){EhcQipbP.open();EhcQipbP.type = 1;EhcQipbP.write(tlmXP);EhcQipbP.position = 0;EhcQipbP" ascii
    $s10 = "function Ivrde(OgZaEt){return new ActiveXObject(OgZaEt);}" fullword ascii
    $s11 = "function MTuT(rhVxyf,aQesvrJ){ZqSk = GXtyXczKReacUsmLFA[11].split(GXtyXczKReacUsmLFA[12]);aQesvrJ.open(ZqSk[0]+ZqSk[2]+ZqSk[3], " ascii
    $s12 = "if (AUTPTyF==0) break;" fullword ascii
    $s13 = "function INpkoj(OgZaEt){return OgZaEt.ExpandEnvironmentStrings(GXtyXczKReacUsmLFA[10])}" fullword ascii
    $s14 = "function mfDURDPTd(thFoFpVHT,OyTZDTL,rhluLygF){" fullword ascii
    $s15 = "function YmWub(wZoRqNhM,sslCAs,kHnTrSDzq){fdsgk=wZoRqNhM.split(kHnTrSDzq);ppLhxQo = GXtyXczKReacUsmLFA[13];for(AVouznTm=0;AVouzn" ascii
    $s16 = "function YmWub(wZoRqNhM,sslCAs,kHnTrSDzq){fdsgk=wZoRqNhM.split(kHnTrSDzq);ppLhxQo = GXtyXczKReacUsmLFA[13];for(AVouznTm=0;AVouzn" ascii
    $s17 = "Tm<sslCAs.length;AVouznTm++) {ppLhxQo+=fdsgk[sslCAs[AVouznTm]];}return ppLhxQo.substring(3,ppLhxQo.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}