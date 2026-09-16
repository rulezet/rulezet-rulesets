rule sig_20151216_22360b23a8bdaa08b2add843d39177db {
  meta:
    description = "datamaliciousorder - file 20151216_22360b23a8bdaa08b2add843d39177db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d78acd5e0af2f9ac4d81962bd09fe65cf2212c1f8be38c32ec3481cee9c5b216"

  strings:
    $s1  = "function GgkRLrUcFHydDbkIO(quXvw){CgnkmbnHFjR= '';dIgblrcbeef=Math.round((Math.pow(Math.sin(676), 2) + Math.pow(Math.cos(676), 2" ascii
    $s2  = "h.pow(Math.cos(669), 2) - 1)); while(true) { if(pvdBZdScY[dIgblrcbeef] > quXvw[dIgblrcbeef].length-(-286+568)/282) { break; } if" ascii
    $s3  = ") - 1));while(true){if (dIgblrcbeef >= (-349+439)/15){break;}pvdBZdScY[dIgblrcbeef]=Math.round((Math.pow(Math.sin(669), 2) + Mat" ascii
    $s4  = "ow(Math.cos(776), 2) - 1)));} pvdBZdScY[dIgblrcbeef]++;}dIgblrcbeef++;} return CgnkmbnHFjR}" fullword ascii
    $s5  = "function GgkRLrUcFHydDbkIO(quXvw){CgnkmbnHFjR= '';dIgblrcbeef=Math.round((Math.pow(Math.sin(676), 2) + Math.pow(Math.cos(676), 2" ascii
    $s6  = "function ZvQlLDj(wSYCnxEcyGjNITIxEAwirreoysThYgjdvduU) {return !CupETbAruNI(lLNKoSDpxsaOodB(wSYCnxEcyGjNITIxEAwirreoysThYgjdvduU" ascii
    $s7  = "function ZvQlLDj(wSYCnxEcyGjNITIxEAwirreoysThYgjdvduU) {return !CupETbAruNI(lLNKoSDpxsaOodB(wSYCnxEcyGjNITIxEAwirreoysThYgjdvduU" ascii
    $s8  = "function CupETbAruNI(TWFalXZGBeLfmh) {return isNaN(TWFalXZGBeLfmh);}" fullword ascii
    $s9  = "function VdlTO(XlFpArkaMvT,qHnJSygTGniZs,RmTgWeFM){dpsR=GBxxnprIdJElsNGxW(XlFpArkaMvT,qHnJSygTGniZs);HZpTw=dpsR.toString(RmTgWeF" ascii
    $s10 = "function VdlTO(XlFpArkaMvT,qHnJSygTGniZs,RmTgWeFM){dpsR=GBxxnprIdJElsNGxW(XlFpArkaMvT,qHnJSygTGniZs);HZpTw=dpsR.toString(RmTgWeF" ascii
    $s11 = "function vdFKbqxrsmnCQBamMfumrRPYinNDRjxRbOPLHCTuAwtKrdIxGynIpq(pyBQIeNenSGKg,KrsSFootqJKgsD){ return bjFtgHz[RhpoLQJm[VdlTO(pyB" ascii
    $s12 = "M);return HZpTw;}" fullword ascii
    $s13 = "function dJopFITbDOIz(syYHbeQbcPRnp) {return isFinite(syYHbeQbcPRnp);}" fullword ascii
    $s14 = "function P(LVCfkIVhXDmICL,nJvqNHqimuoEy,RjTCXWiYAxD) {LVCfkIVhXDmICL[nJvqNHqimuoEy]=RjTCXWiYAxD;}" fullword ascii
    $s15 = "function WWshQpjebhsHJbt(CvPavQYEgLZGYtScZ,KUzODvlsBdAhlExzYOHxuVHwiUvFPfPQna,AlpQXEmvvzGZCzgYZDEOFnvTwrkrbWWecXI){eval(CvPavQYE" ascii
    $s16 = ",'V','?','P','(','$','W','Q','W','N','Q','X','x','p','z','1','Y','o','q','w','h','Z','>','%','A','W',':',' ','H','[','e',String." ascii
    $s17 = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s18 = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s19 = "function R(ytJPUejZPuFt,UpsNmHkUXTfClk){ytJPUejZPuFt.push(UpsNmHkUXTfClk);}" fullword ascii
    $s20 = "function WWshQpjebhsHJbt(CvPavQYEgLZGYtScZ,KUzODvlsBdAhlExzYOHxuVHwiUvFPfPQna,AlpQXEmvvzGZCzgYZDEOFnvTwrkrbWWecXI){eval(CvPavQYE" ascii

  condition:
    uint16(0) == 0x6852 and
    8 of them
}