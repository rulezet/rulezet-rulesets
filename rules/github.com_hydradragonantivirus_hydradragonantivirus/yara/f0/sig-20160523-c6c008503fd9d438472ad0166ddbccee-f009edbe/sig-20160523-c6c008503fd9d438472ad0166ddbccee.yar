rule sig_20160523_c6c008503fd9d438472ad0166ddbccee {
  meta:
    description = "datamaliciousorder - file 20160523_c6c008503fd9d438472ad0166ddbccee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1143b0bb5cae1e2d1861cfab5fe4a46153e0c1f7d15a9afcf7c6754b71852db"

  strings:
    $s1  = "function NtcXBZlPrz(fPvMIAyd,ubLrmYVSJwlA) {fPvMIAyd.Run(ubLrmYVSJwlA, 0x1, 0x0);}" fullword ascii
    $s2  = "function jChdGcYC(Tcfpo) {var aFEIVeet=yAZCgzYQefzxTKkKIQUx[2];for(var kGcoU=0;kGcoU<Tcfpo;kGcoU++){RjKuP+=aFEIVeet.charAt(Math." ascii
    $s3  = "function jChdGcYC(Tcfpo) {var aFEIVeet=yAZCgzYQefzxTKkKIQUx[2];for(var kGcoU=0;kGcoU<Tcfpo;kGcoU++){RjKuP+=aFEIVeet.charAt(Math." ascii
    $s4  = "function cZILZYz(Mqqgg) {Mqqgg.close();}" fullword ascii
    $s5  = "function bBLjI(pDdQcrVk,hARcvd,wclxNxtIx){IZqdP=pDdQcrVk.split(wclxNxtIx);cxeVjMW = yAZCgzYQefzxTKkKIQUx[13];for(XmhEOITN=0;XmhE" ascii
    $s6  = "function brBLY(yCrirm){return new ActiveXObject(yCrirm);}" fullword ascii
    $s7  = "function rYrToakIo(PvwLmfYFF,dfZfhOy,yKAhVBlG){" fullword ascii
    $s8  = "floor(Math.random()*aFEIVeet.length));}return RjKuP;}" fullword ascii
    $s9  = "try{XNFCHbm=rYrToakIo(UkXgZ[hfmm], zcIpnLS() + yAZCgzYQefzxTKkKIQUx[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function EKBn(hjTpWx,iiNxZDY){JxMx = yAZCgzYQefzxTKkKIQUx[11].split(yAZCgzYQefzxTKkKIQUx[12]);iiNxZDY.open(JxMx[0]+JxMx[2]+JxMx[" ascii
    $s11 = "function FNHOr(Vaiscirb,JkAkL,KwkJOpUBbR){LQeY(Vaiscirb);AcXwHvxG(Vaiscirb);sLAgfHC(Vaiscirb,JkAkL);zxjshqCWt(Vaiscirb);nCos(Vai" ascii
    $s12 = "function AcXwHvxG(zERupxfqO) {zERupxfqO.type=1;}" fullword ascii
    $s13 = "function EKBn(hjTpWx,iiNxZDY){JxMx = yAZCgzYQefzxTKkKIQUx[11].split(yAZCgzYQefzxTKkKIQUx[12]);iiNxZDY.open(JxMx[0]+JxMx[2]+JxMx[" ascii
    $s14 = "function IspeQM(yCrirm){return yCrirm.ExpandEnvironmentStrings(yAZCgzYQefzxTKkKIQUx[10])}" fullword ascii
    $s15 = "3], hjTpWx, false);iiNxZDY.send();}" fullword ascii
    $s16 = "function nCos(DLSpRpX,ncRnBIx) {DLSpRpX.saveToFile(ncRnBIx, 2);}" fullword ascii
    $s17 = "function sLAgfHC(fdrA,UePbm) {fdrA.write(UePbm);}" fullword ascii
    $s18 = "function bBLjI(pDdQcrVk,hARcvd,wclxNxtIx){IZqdP=pDdQcrVk.split(wclxNxtIx);cxeVjMW = yAZCgzYQefzxTKkKIQUx[13];for(XmhEOITN=0;XmhE" ascii
    $s19 = "if (XNFCHbm==0) break;" fullword ascii
    $s20 = "function LQeY(pSvjUK) {pSvjUK.open();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}