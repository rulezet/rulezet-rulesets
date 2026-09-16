rule sig_20160520_01a03a3d82c6c812e2908f91bd501c93 {
  meta:
    description = "datamaliciousorder - file 20160520_01a03a3d82c6c812e2908f91bd501c93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d130936e30bd50231305cbf47f4d73d05df7dc4ebffd3c85904dea9d81423e"

  strings:
    $s1  = "function CKhtoseo(DJrTp) {var GzUPIIDV=irLPOtzbwhpWnszV[2];for(var MwEYt=0;MwEYt<DJrTp;MwEYt++){UiSzH+=GzUPIIDV.charAt(Math.floo" ascii
    $s2  = "function CKhtoseo(DJrTp) {var GzUPIIDV=irLPOtzbwhpWnszV[2];for(var MwEYt=0;MwEYt<DJrTp;MwEYt++){UiSzH+=GzUPIIDV.charAt(Math.floo" ascii
    $s3  = "function XWpJ(lVPrAK,eHmsuww){zwdA = irLPOtzbwhpWnszV[11].split(irLPOtzbwhpWnszV[12]);eHmsuww.open(zwdA[0]+zwdA[2]+zwdA[3], lVPr" ascii
    $s4  = "function EnFFI(PVurZCTx,PeNqKG,pPJNkmjFI){obKla=PVurZCTx.split(pPJNkmjFI);rnjUayq = irLPOtzbwhpWnszV[13];for(ziLwUhlK=0;ziLwUhlK" ascii
    $s5  = "function TSZEe(qPiFjH){return new ActiveXObject(qPiFjH);}" fullword ascii
    $s6  = "AK, false);eHmsuww.send();}" fullword ascii
    $s7  = "try{yTFTflbcj(Zwloz[Jrjm], liKlVYx() + irLPOtzbwhpWnszV[9], 1)}catch(e){}; " fullword ascii
    $s8  = "<PeNqKG.length;ziLwUhlK++) {rnjUayq+=obKla[PeNqKG[ziLwUhlK]];}return rnjUayq.substring(3,rnjUayq.length);}" fullword ascii
    $s9  = "function jqvitC(qPiFjH){return qPiFjH.ExpandEnvironmentStrings(irLPOtzbwhpWnszV[10])}" fullword ascii
    $s10 = "function DhIqY(nLdfzcDW,xshVm,TIawpwKgTr){nLdfzcDW.open();nLdfzcDW.type = 1;nLdfzcDW.write(xshVm);nLdfzcDW.position = 0;nLdfzcDW" ascii
    $s11 = "r(Math.random()*GzUPIIDV.length));}return UiSzH;}" fullword ascii
    $s12 = "function XWpJ(lVPrAK,eHmsuww){zwdA = irLPOtzbwhpWnszV[11].split(irLPOtzbwhpWnszV[12]);eHmsuww.open(zwdA[0]+zwdA[2]+zwdA[3], lVPr" ascii
    $s13 = "function liKlVYx() {var QjaX=100000;var spelwX = 100;return Math.random()*(QjaX-spelwX)+spelwX;}" fullword ascii
    $s14 = "function EnFFI(PVurZCTx,PeNqKG,pPJNkmjFI){obKla=PVurZCTx.split(pPJNkmjFI);rnjUayq = irLPOtzbwhpWnszV[13];for(ziLwUhlK=0;ziLwUhlK" ascii
    $s15 = "function yTFTflbcj(NRTxPyyek,WvRqIPV,ZHkcDrNw){" fullword ascii
    $s16 = "function DhIqY(nLdfzcDW,xshVm,TIawpwKgTr){nLdfzcDW.open();nLdfzcDW.type = 1;nLdfzcDW.write(xshVm);nLdfzcDW.position = 0;nLdfzcDW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}