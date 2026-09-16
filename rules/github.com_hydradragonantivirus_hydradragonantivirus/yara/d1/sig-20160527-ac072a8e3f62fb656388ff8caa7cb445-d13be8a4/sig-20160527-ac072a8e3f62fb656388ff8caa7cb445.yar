rule sig_20160527_ac072a8e3f62fb656388ff8caa7cb445 {
  meta:
    description = "datamaliciousorder - file 20160527_ac072a8e3f62fb656388ff8caa7cb445.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaa80fa01382058cd43b1303436d3913ef64eab6487287d4ffbb154e4701342b"

  strings:
    $s1  = "function JtsaLdshxyD() {return WScript;}function XJqIjnCLNglM(){return oriPrs.ExpandEnvironmentStrings(aimeRMcoOPj())}" fullword ascii
    $s2  = "function wXklsniuzKCDs(bsyZLfWjyBqHh,fBrggiZNx){return bsyZLfWjyBqHh.charAt(fBrggiZNx);}" fullword ascii
    $s3  = "ing.fromCharCode(92)+TTnNVbGtzIBETKzucmIqk[4],true);" fullword ascii
    $s4  = "function aimeRMcoOPj(){return wFCPCl(TTnNVbGtzIBETKzucmIqk[8],[1,5,7],TTnNVbGtzIBETKzucmIqk[9]);}" fullword ascii
    $s5  = "X=0;psDVbX<QaVbxAODe.length;psDVbX++) {tfSoeXbTihlus+=lIEQmx[QaVbxAODe[psDVbX]];}return tfSoeXbTihlus.substring(3,tfSoeXbTihlus." ascii
    $s6  = "function pj(MtGHld){return String.fromCharCode(MtGHld);}" fullword ascii
    $s7  = "function jaRaAaroLbIO(zkgErnhNuNulC) {var valuGsoFHDvXfBWyhDrT = IplbKuoUElQbXcQaUQZ.join(TTnNVbGtzIBETKzucmIqk[6]);var eGaEMYBB" ascii
    $s8  = "function wFCPCl(ONwTbJCoov,QaVbxAODe,NSkymD){lIEQmx=ONwTbJCoov.split(NSkymD);tfSoeXbTihlus = TTnNVbGtzIBETKzucmIqk[14];for(psDVb" ascii
    $s9  = "function JxPqoBlsSZYciGYgwONRNUn(oXidqHSgDAfCwHKpCmHkX,QavBGZuXwVPIfwqvMyl){return String.fromCharCode(oXidqHSgDAfCwHKpCmHkX,Qav" ascii
    $s10 = "TiUqzjzQ = RAyEZQNqBd & 0xff;if (PfsuQiSOql == 64) pGtiuz += pj(eGaEMYBBZYsncrO);else if (VoQneoDyAuNBeXSbp == 64) pGtiuz += JxP" ascii
    $s11 = "function wFCPCl(ONwTbJCoov,QaVbxAODe,NSkymD){lIEQmx=ONwTbJCoov.split(NSkymD);tfSoeXbTihlus = TTnNVbGtzIBETKzucmIqk[14];for(psDVb" ascii
    $s12 = "var mOwsrBiffqa=function(){return new ActiveXObject(TTnNVbGtzIBETKzucmIqk[0]);}();" fullword ascii
    $s13 = "function JxPqoBlsSZYciGYgwONRNUn(oXidqHSgDAfCwHKpCmHkX,QavBGZuXwVPIfwqvMyl){return String.fromCharCode(oXidqHSgDAfCwHKpCmHkX,Qav" ascii
    $s14 = "function zIHBnjBQWYoTxZumvsh(njkyRpmMbY,APZdXkSrYSR,rGUGyJyLXMumI){return String.fromCharCode(njkyRpmMbY,APZdXkSrYSR,rGUGyJyLXMu" ascii
    $s15 = "qoBlsSZYciGYgwONRNUn(eGaEMYBBZYsncrO, IOlIetkV);else pGtiuz += zIHBnjBQWYoTxZumvsh(eGaEMYBBZYsncrO, IOlIetkV, HXdlhbnVDRyqRGpBTi" ascii
    $s16 = "function hDdkJiwHdLhUXnovNg(TiAqBWNZrREhKnWjhTVzfYKw,dIIjocqLIc){return TiAqBWNZrREhKnWjhTVzfYKw.indexOf(dIIjocqLIc);}" fullword ascii
    $s17 = "function PAEIv(){return wFCPCl(TTnNVbGtzIBETKzucmIqk[10],[2,4,8,10],TTnNVbGtzIBETKzucmIqk[11]);}" fullword ascii
    $s18 = "function jaRaAaroLbIO(zkgErnhNuNulC) {var valuGsoFHDvXfBWyhDrT = IplbKuoUElQbXcQaUQZ.join(TTnNVbGtzIBETKzucmIqk[6]);var eGaEMYBB" ascii
    $s19 = "function gmyGd(hNNBWKFvuTwtIa,bEjiLICu) {var SExMGwy=[TTnNVbGtzIBETKzucmIqk[15]];hNNBWKFvuTwtIa[SExMGwy[0]](bEjiLICu,0x1,0x0)}" fullword ascii
    $s20 = "function zIHBnjBQWYoTxZumvsh(njkyRpmMbY,APZdXkSrYSR,rGUGyJyLXMumI){return String.fromCharCode(njkyRpmMbY,APZdXkSrYSR,rGUGyJyLXMu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}