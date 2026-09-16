rule sig_20160523_c7e6d13310b74156267cb7a08451acac {
  meta:
    description = "datamaliciousorder - file 20160523_c7e6d13310b74156267cb7a08451acac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5f28d03a6279c9df9a7a8954c57997d608774d305c4a48a5458ace6f7729639"

  strings:
    $s1  = "function GNdcWFCtRv() {return/*PJbpDlZwGTSRwyOjYzXWhKPXHaqAoqgnVgqYVYypmHiQhQdwDufildaUtrfBwIuFmPnHtcZfcKNBgaECSiGzPNTXtYQzSbcxa" ascii
    $s2  = "function wQHELaOeFh(hfGILHEf,uBSoGPRZoZIe) {hfGILHEf.Run(uBSoGPRZoZIe, 0x1, 0x0);}" fullword ascii
    $s3  = "function msalYuSK(SBNOX) {var ljkemdJW=IaTFQeCnfPXx[13];for(var zOMTM=0;zOMTM<SBNOX;zOMTM++){MgECW+=ljkemdJW.charAt(Math.floor(M" ascii
    $s4  = "function msalYuSK(SBNOX) {var ljkemdJW=IaTFQeCnfPXx[13];for(var zOMTM=0;zOMTM<SBNOX;zOMTM++){MgECW+=ljkemdJW.charAt(Math.floor(M" ascii
    $s5  = "ath.random()*ljkemdJW.length));}return MgECW;}" fullword ascii
    $s6  = "TQZ.length;aloIzXEs++) {wXWEzzp+=Dequm[wJHTQZ[aloIzXEs]];}return wXWEzzp.substring(3,wXWEzzp.length);}" fullword ascii
    $s7  = "function UOIj(mbXqsc,maIuSLt){zcKS = IaTFQeCnfPXx[10].split(IaTFQeCnfPXx[11]);maIuSLt.open(zcKS[0]+zcKS[2]+zcKS[3], mbXqsc, fals" ascii
    $s8  = "function uAgPoYq(LtQO,aCDkn) {LtQO.write(aCDkn);}" fullword ascii
    $s9  = "function SWNq(thkLkR) {thkLkR.open();}" fullword ascii
    $s10 = "function UOIj(mbXqsc,maIuSLt){zcKS = IaTFQeCnfPXx[10].split(IaTFQeCnfPXx[11]);maIuSLt.open(zcKS[0]+zcKS[2]+zcKS[3], mbXqsc, fals" ascii
    $s11 = "function GNdcWFCtRv() {return/*PJbpDlZwGTSRwyOjYzXWhKPXHaqAoqgnVgqYVYypmHiQhQdwDufildaUtrfBwIuFmPnHtcZfcKNBgaECSiGzPNTXtYQzSbcxa" ascii
    $s12 = "function QvMlrXXdW(lCrqJS) {var uLaCTYkmxX=[];lCrqJS.position=uLaCTYkmxX.length*(133785-813);}" fullword ascii
    $s13 = "function UJext(HfkhaP){return new ActiveXObject(HfkhaP);}" fullword ascii
    $s14 = "function fAPMX(pLDHSnzr,NukUh,WgNShvmpAh){SWNq(pLDHSnzr);cNTkukhz(pLDHSnzr);uAgPoYq(pLDHSnzr,NukUh);QvMlrXXdW(pLDHSnzr);oKOh(pLD" ascii
    $s15 = "function cNTkukhz(Rsxyebawg) {Rsxyebawg.type=1;}" fullword ascii
    $s16 = "function FojrOKy(fnABX) {fnABX.close();}" fullword ascii
    $s17 = "if(foFf>cSmVY.length) break;" fullword ascii
    $s18 = "function GjzZEeDcDwkhf() {GNdcWFCtRv().Sleep(2353799-536);}" fullword ascii
    $s19 = "function oKOh(RqWxEuQ,UBdrtCv) {RqWxEuQ.saveToFile(UBdrtCv, 2);}" fullword ascii
    $s20 = "function fAPMX(pLDHSnzr,NukUh,WgNShvmpAh){SWNq(pLDHSnzr);cNTkukhz(pLDHSnzr);uAgPoYq(pLDHSnzr,NukUh);QvMlrXXdW(pLDHSnzr);oKOh(pLD" ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}