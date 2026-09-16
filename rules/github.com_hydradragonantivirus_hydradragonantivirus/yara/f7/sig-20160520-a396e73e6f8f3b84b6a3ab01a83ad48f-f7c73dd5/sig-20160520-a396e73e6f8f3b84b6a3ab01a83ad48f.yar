rule sig_20160520_a396e73e6f8f3b84b6a3ab01a83ad48f {
  meta:
    description = "datamaliciousorder - file 20160520_a396e73e6f8f3b84b6a3ab01a83ad48f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "702962fa2e223366668c45b86f4c29f58fd8c8fee9bd88e52b5bd6c36cc38b1b"

  strings:
    $s1  = "function sUzvclIs(UucmT) {var XsuwbPID=SPWuJzByrUXLrDgxUl[2];for(var keuLD=0;keuLD<UucmT;keuLD++){ywTLH+=XsuwbPID.charAt(Math.fl" ascii
    $s2  = "function sUzvclIs(UucmT) {var XsuwbPID=SPWuJzByrUXLrDgxUl[2];for(var keuLD=0;keuLD<UucmT;keuLD++){ywTLH+=XsuwbPID.charAt(Math.fl" ascii
    $s3  = "function elhFE(DCoMIkgf,nwGPC,fNunBYaFEn){DCoMIkgf.open();DCoMIkgf.type = 1;DCoMIkgf.write(nwGPC);DCoMIkgf.position = 0;DCoMIkgf" ascii
    $s4  = "function elhFE(DCoMIkgf,nwGPC,fNunBYaFEn){DCoMIkgf.open();DCoMIkgf.type = 1;DCoMIkgf.write(nwGPC);DCoMIkgf.position = 0;DCoMIkgf" ascii
    $s5  = "try{nCoMnAsFX(sVpKw[KnQf], AmsUzas() + SPWuJzByrUXLrDgxUl[9], 1)}catch(e){}; " fullword ascii
    $s6  = "oor(Math.random()*XsuwbPID.length));}return ywTLH;}" fullword ascii
    $s7  = "function BWTevB(jPIIXF){return jPIIXF.ExpandEnvironmentStrings(SPWuJzByrUXLrDgxUl[10])}" fullword ascii
    $s8  = "function AmsUzas() {var xicP=100000;var svsooB = 100;return Math.random()*(xicP-svsooB)+svsooB;}" fullword ascii
    $s9  = "function VsLPz(dOgkFcuc,ClVzZB,DzCLIBoYd){YfScP=dOgkFcuc.split(DzCLIBoYd);DFfAjai = SPWuJzByrUXLrDgxUl[13];for(CQagcldI=0;CQagcl" ascii
    $s10 = "function VsLPz(dOgkFcuc,ClVzZB,DzCLIBoYd){YfScP=dOgkFcuc.split(DzCLIBoYd);DFfAjai = SPWuJzByrUXLrDgxUl[13];for(CQagcldI=0;CQagcl" ascii
    $s11 = "function kqFd(fEvtpi,tISnqSu){EFya = SPWuJzByrUXLrDgxUl[11].split(SPWuJzByrUXLrDgxUl[12]);tISnqSu.open(EFya[0]+EFya[2]+EFya[3], " ascii
    $s12 = "function NZXyn(jPIIXF){return new ActiveXObject(jPIIXF);}" fullword ascii
    $s13 = "function kqFd(fEvtpi,tISnqSu){EFya = SPWuJzByrUXLrDgxUl[11].split(SPWuJzByrUXLrDgxUl[12]);tISnqSu.open(EFya[0]+EFya[2]+EFya[3], " ascii
    $s14 = "fEvtpi, false);tISnqSu.send();}" fullword ascii
    $s15 = "dI<ClVzZB.length;CQagcldI++) {DFfAjai+=YfScP[ClVzZB[CQagcldI]];}return DFfAjai.substring(3,DFfAjai.length);}" fullword ascii
    $s16 = "function nCoMnAsFX(rEhHAeDlZ,wFZnLyQ,nCTczacA){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}