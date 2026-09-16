rule sig_20151211_6be29a772594c7402e1b5af46136df48 {
  meta:
    description = "datamaliciousorder - file 20151211_6be29a772594c7402e1b5af46136df48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bcfa3caab846a7688f2023a23394a01f106dcc9d1542b254917e4c4dff07339"

  strings:
    $s1  = "function IrxIt(WlsOnoPUwQL,RhsFEGiBvKyEi,oqagwARr){Jcfe=parseInt(WlsOnoPUwQL,RhsFEGiBvKyEi);pkZmZ=Jcfe.toString(oqagwARr);return" ascii
    $s2  = "function luVNExc(NlinosAHbTNhakHwueEFwXfSBGrxCuBeLUii) {return !isNaN(parseFloat(NlinosAHbTNhakHwueEFwXfSBGrxCuBeLUii)) && isFin" ascii
    $s3  = "function luVNExc(NlinosAHbTNhakHwueEFwXfSBGrxCuBeLUii) {return !isNaN(parseFloat(NlinosAHbTNhakHwueEFwXfSBGrxCuBeLUii)) && isFin" ascii
    $s4  = " pkZmZ;}function ccvXhbdUiOvitTb(tPKkbNkQJTmPAyLEp){eval(tPKkbNkQJTmPAyLEp)}" fullword ascii
    $s5  = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"37\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function VjFqTHurmqtPIXVHADFTKYagAASNPlLbBpJMzcyQznedGTSBBNFUdg(PbZTITbQguOvO,FRwgqMXymZllAn){ return sHjQV[IrxIt(PbZTITbQguOvO[" ascii
    $s7  = "var Z=new Array(\"2e\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"52\",\"" ascii
    $s8  = "RDNLwnEvG[bMXXPRpAhUk]=(-448+448)/856; while(true) { if(RDNLwnEvG[bMXXPRpAhUk] > YVAZk[bMXXPRpAhUk].length-(-35+140)/105) { brea" ascii
    $s9  = "function MlhIzdPZPoDOwIMyz(YVAZk){sfGKPFjfYWJ= '';bMXXPRpAhUk=(-678+678)/697; while(true){if(bMXXPRpAhUk >= (350+478)/414)break;" ascii
    $s10 = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"37\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "++;}bMXXPRpAhUk++;} return sfGKPFjfYWJ}" fullword ascii
    $s12 = "function VjFqTHurmqtPIXVHADFTKYagAASNPlLbBpJMzcyQznedGTSBBNFUdg(PbZTITbQguOvO,FRwgqMXymZllAn){ return sHjQV[IrxIt(PbZTITbQguOvO[" ascii
    $s13 = "function MlhIzdPZPoDOwIMyz(YVAZk){sfGKPFjfYWJ= '';bMXXPRpAhUk=(-678+678)/697; while(true){if(bMXXPRpAhUk >= (350+478)/414)break;" ascii
    $s14 = "var Z=new Array(\"2e\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"52\",\"" ascii
    $s15 = "function WoWVacmBoeP(PGFyXNIP,ylcvQp){return PGFyXNIP.split(ylcvQp)}" fullword ascii
    $s16 = "function IrxIt(WlsOnoPUwQL,RhsFEGiBvKyEi,oqagwARr){Jcfe=parseInt(WlsOnoPUwQL,RhsFEGiBvKyEi);pkZmZ=Jcfe.toString(oqagwARr);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}