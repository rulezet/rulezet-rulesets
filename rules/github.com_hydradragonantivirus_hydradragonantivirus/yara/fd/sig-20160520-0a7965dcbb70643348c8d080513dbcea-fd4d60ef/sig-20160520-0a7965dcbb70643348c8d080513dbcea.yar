rule sig_20160520_0a7965dcbb70643348c8d080513dbcea {
  meta:
    description = "datamaliciousorder - file 20160520_0a7965dcbb70643348c8d080513dbcea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d2bfb483229b437f1e746004a162e28f1ece2fa291efd13d570d5088c992c0c"

  strings:
    $s1  = "function MfwLSazr(PIXpD) {var IAZGfvlV=XTAmrT[2];for(var ErsVk=0;ErsVk<PIXpD;ErsVk++){ClFCL+=IAZGfvlV.charAt(Math.floor(Math.ran" ascii
    $s2  = "function MfwLSazr(PIXpD) {var IAZGfvlV=XTAmrT[2];for(var ErsVk=0;ErsVk<PIXpD;ErsVk++){ClFCL+=IAZGfvlV.charAt(Math.floor(Math.ran" ascii
    $s3  = "try{cwnvkarSy(VAUjN[RXod], hRKiDnA() + XTAmrT[9], 1)}catch(e){}; " fullword ascii
    $s4  = "function gPFgB(dSyBQl){return new ActiveXObject(dSyBQl);}" fullword ascii
    $s5  = "function paoQA(SylnIrzk,hlftA,YavzWLuoXi){SylnIrzk.open();SylnIrzk.type = 1;SylnIrzk.write(hlftA);SylnIrzk.position = 0;SylnIrzk" ascii
    $s6  = "ngth;ctRXNVfk++) {pFtcSOy+=GSoMc[ZhnvQU[ctRXNVfk]];}return pFtcSOy.substring(3,pFtcSOy.length);}" fullword ascii
    $s7  = "dom()*IAZGfvlV.length));}return ClFCL;}" fullword ascii
    $s8  = "function cqvTb(EsSSGKkA,ZhnvQU,TEJLtyIOG){GSoMc=EsSSGKkA.split(TEJLtyIOG);pFtcSOy = XTAmrT[13];for(ctRXNVfk=0;ctRXNVfk<ZhnvQU.le" ascii
    $s9  = "function WeJyRJ(dSyBQl){return dSyBQl.ExpandEnvironmentStrings(XTAmrT[10])}" fullword ascii
    $s10 = "function VGsR(cLaJvq,njfFVqK){qsCq = XTAmrT[11].split(XTAmrT[12]);njfFVqK.open(qsCq[0]+qsCq[2]+qsCq[3], cLaJvq, false);njfFVqK.s" ascii
    $s11 = "function cqvTb(EsSSGKkA,ZhnvQU,TEJLtyIOG){GSoMc=EsSSGKkA.split(TEJLtyIOG);pFtcSOy = XTAmrT[13];for(ctRXNVfk=0;ctRXNVfk<ZhnvQU.le" ascii
    $s12 = "function VGsR(cLaJvq,njfFVqK){qsCq = XTAmrT[11].split(XTAmrT[12]);njfFVqK.open(qsCq[0]+qsCq[2]+qsCq[3], cLaJvq, false);njfFVqK.s" ascii
    $s13 = "function paoQA(SylnIrzk,hlftA,YavzWLuoXi){SylnIrzk.open();SylnIrzk.type = 1;SylnIrzk.write(hlftA);SylnIrzk.position = 0;SylnIrzk" ascii
    $s14 = "function cwnvkarSy(gAikoTBmw,bKVcdUe,fEPedIJN){" fullword ascii
    $s15 = "function hRKiDnA() {var SiIK=100000;var eLZTBH = 100;return Math.random()*(SiIK-eLZTBH)+eLZTBH;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}