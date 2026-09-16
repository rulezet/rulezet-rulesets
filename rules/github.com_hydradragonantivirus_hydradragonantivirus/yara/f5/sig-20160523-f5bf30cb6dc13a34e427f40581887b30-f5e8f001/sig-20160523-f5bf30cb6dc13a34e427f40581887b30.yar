rule sig_20160523_f5bf30cb6dc13a34e427f40581887b30 {
  meta:
    description = "datamaliciousorder - file 20160523_f5bf30cb6dc13a34e427f40581887b30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64fd0a48d00fec9c6b82fb76e440cad8af19052899a329128c119a2b8f4897ef"

  strings:
    $s1  = "function cYQHJyyV(vjgbo) {var JppnHPEH=CsijFiJtkNbFDsab[13];for(var mwFeA=0;mwFeA<vjgbo;mwFeA++){sOlxJ+=JppnHPEH.charAt(Math.flo" ascii
    $s2  = "function aNVRqERJPP(pqUYUujq,XTqKHYQHjPSL) {pqUYUujq.Run(XTqKHYQHjPSL, 0x1, 0x0);}" fullword ascii
    $s3  = "function GUZOsYbxTN() {return/*MhJoMkfMBuOZEwEdIvQxmryPmqkPcBYDKObPCJaAflbUxEzpXunouapsJUngcYTjLTdYmXsIoVEjqnvMHVPHuFKcgnzshNXJM" ascii
    $s4  = "function cYQHJyyV(vjgbo) {var JppnHPEH=CsijFiJtkNbFDsab[13];for(var mwFeA=0;mwFeA<vjgbo;mwFeA++){sOlxJ+=JppnHPEH.charAt(Math.flo" ascii
    $s5  = "function lUlvRCp(){return Math.random();}" fullword ascii
    $s6  = "function BWlEcKFQ(uCBWlqbcI) {uCBWlqbcI.type=1;}" fullword ascii
    $s7  = "function yWmKj(SYcwptNo,ynwAmK,AnGVWpYxO){EELra=SYcwptNo.split(AnGVWpYxO);mHmsRKs = CsijFiJtkNbFDsab[12];for(VqOxRcRj=0;VqOxRcRj" ascii
    $s8  = "function GUZOsYbxTN() {return/*MhJoMkfMBuOZEwEdIvQxmryPmqkPcBYDKObPCJaAflbUxEzpXunouapsJUngcYTjLTdYmXsIoVEjqnvMHVPHuFKcgnzshNXJM" ascii
    $s9  = "function TZGlp(dvVKvGvD,Nliys,dfqUskOPYh){owYt(dvVKvGvD);BWlEcKFQ(dvVKvGvD);JEZbYXR(dvVKvGvD,Nliys);IunxoOqlq(dvVKvGvD);nbGC(dvV" ascii
    $s10 = "function yWmKj(SYcwptNo,ynwAmK,AnGVWpYxO){EELra=SYcwptNo.split(AnGVWpYxO);mHmsRKs = CsijFiJtkNbFDsab[12];for(VqOxRcRj=0;VqOxRcRj" ascii
    $s11 = "function uTzDWl(SmvMrV){return SmvMrV.ExpandEnvironmentStrings(CsijFiJtkNbFDsab[9])}" fullword ascii
    $s12 = "function cqtqFyH() {var MKmi=100000;var eTzdpQ = 100;return lUlvRCp()*(MKmi-eTzdpQ)+eTzdpQ;}" fullword ascii
    $s13 = "wT, false);hOuhgJn.send();}" fullword ascii
    $s14 = "function nbGC(PoNRrrz,qoCFhQw) {PoNRrrz.saveToFile(qoCFhQw, 2);}" fullword ascii
    $s15 = "function IOIi(ozFewT,hOuhgJn){jQSc = CsijFiJtkNbFDsab[10].split(CsijFiJtkNbFDsab[11]);hOuhgJn.open(jQSc[0]+jQSc[2]+jQSc[3], ozFe" ascii
    $s16 = "function UxbXoeBFETxQQ() {GUZOsYbxTN().Sleep(2315849-957);}" fullword ascii
    $s17 = "or(Math.random()*JppnHPEH.length));}return sOlxJ;}" fullword ascii
    $s18 = "if(TXVH>OBLBV.length) break;" fullword ascii
    $s19 = "function owYt(wRhkLA) {wRhkLA.open();}" fullword ascii
    $s20 = "function IunxoOqlq(PgaoOZ) {var bUYfSYQpne=[];PgaoOZ.position=bUYfSYQpne.length*(6332695-671);}" fullword ascii

  condition:
    uint16(0) == 0x0327 and
    8 of them
}