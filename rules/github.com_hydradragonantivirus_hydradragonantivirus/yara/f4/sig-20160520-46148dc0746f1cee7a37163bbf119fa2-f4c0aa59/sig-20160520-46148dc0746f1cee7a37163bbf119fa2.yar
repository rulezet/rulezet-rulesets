rule sig_20160520_46148dc0746f1cee7a37163bbf119fa2 {
  meta:
    description = "datamaliciousorder - file 20160520_46148dc0746f1cee7a37163bbf119fa2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4803a6baf49fecddf04fc3a883a88d6215e48adbe7d7c7510236a6d9cfe3a69"

  strings:
    $s1  = "function JVsGxIKd(gKHbX) {var RhdGxJqt=WlOmjvoOGxkFXC[2];for(var skrVV=0;skrVV<gKHbX;skrVV++){knyXG+=RhdGxJqt.charAt(Math.floor(" ascii
    $s2  = "function JVsGxIKd(gKHbX) {var RhdGxJqt=WlOmjvoOGxkFXC[2];for(var skrVV=0;skrVV<gKHbX;skrVV++){knyXG+=RhdGxJqt.charAt(Math.floor(" ascii
    $s3  = "Math.random()*RhdGxJqt.length));}return knyXG;}" fullword ascii
    $s4  = "aUwoW.length;PaBspPyO++) {NqbjSuo+=cypAH[SaUwoW[PaBspPyO]];}return NqbjSuo.substring(3,NqbjSuo.length);}" fullword ascii
    $s5  = "function gQfdXk(ErcYWj){return ErcYWj.ExpandEnvironmentStrings(WlOmjvoOGxkFXC[10])}" fullword ascii
    $s6  = "false);pudrApO.send();}" fullword ascii
    $s7  = "function IZlKZ(JMevmLzb,SaUwoW,NLLrdyTFn){cypAH=JMevmLzb.split(NLLrdyTFn);NqbjSuo = WlOmjvoOGxkFXC[13];for(PaBspPyO=0;PaBspPyO<S" ascii
    $s8  = "function aSLMd(ErcYWj){return new ActiveXObject(ErcYWj);}" fullword ascii
    $s9  = "function oZebW(BEAbRjZN,NRdRH,bSzrLVwiss){BEAbRjZN.open();BEAbRjZN.type = 1;BEAbRjZN.write(NRdRH);BEAbRjZN.position = 0;BEAbRjZN" ascii
    $s10 = "function oZebW(BEAbRjZN,NRdRH,bSzrLVwiss){BEAbRjZN.open();BEAbRjZN.type = 1;BEAbRjZN.write(NRdRH);BEAbRjZN.position = 0;BEAbRjZN" ascii
    $s11 = "try{LuEpgcl=EatiKVXLe(xrcIE[kaXN], lYlaBmr() + WlOmjvoOGxkFXC[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function lYlaBmr() {var JUCr=100000;var dtgehF = 100;return Math.random()*(JUCr-dtgehF)+dtgehF;}" fullword ascii
    $s13 = "function VZXN(FhWnNz,pudrApO){DBCF = WlOmjvoOGxkFXC[11].split(WlOmjvoOGxkFXC[12]);pudrApO.open(DBCF[0]+DBCF[2]+DBCF[3], FhWnNz, " ascii
    $s14 = "function EatiKVXLe(ytMFihRkz,KjZcLfw,WxxALEEI){" fullword ascii
    $s15 = "function IZlKZ(JMevmLzb,SaUwoW,NLLrdyTFn){cypAH=JMevmLzb.split(NLLrdyTFn);NqbjSuo = WlOmjvoOGxkFXC[13];for(PaBspPyO=0;PaBspPyO<S" ascii
    $s16 = "function VZXN(FhWnNz,pudrApO){DBCF = WlOmjvoOGxkFXC[11].split(WlOmjvoOGxkFXC[12]);pudrApO.open(DBCF[0]+DBCF[2]+DBCF[3], FhWnNz, " ascii
    $s17 = "if (LuEpgcl==0) break;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}