rule sig_20160527_6ef3e52c582f14da9ac5e26279815b02 {
  meta:
    description = "datamaliciousorder - file 20160527_6ef3e52c582f14da9ac5e26279815b02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24c0c3e9aa61cb92b02ef85418ba78d9ce02cb3dec8c11c459108a93b76536d"

  strings:
    $s1  = "function jOvvcYVu() {return WScript;}function HVsNCcpYAf(){return VuzXKGtTn.ExpandEnvironmentStrings(AByfZeqjKcKINE())}" fullword ascii
    $s2  = "function BdsIidCVMLrGMQGDp(urJhHIWCQ,xkQMieNEdtfxp){return urJhHIWCQ.charAt(xkQMieNEdtfxp);}" fullword ascii
    $s3  = "function nr(VZVnKFBlU){return String.fromCharCode(VZVnKFBlU);}" fullword ascii
    $s4  = "function NoaSzQ(VNpvDSCzPVKiY) {var OzlkLuZEEArb = TBuXL.join(iFCrqdYJRCVXjcsEkWFSr[6]);var RnosAJFgCJhNAPxM, pmKdQprh, ExNZieTk" ascii
    $s5  = "function qgMGJ(){return vwcCW(iFCrqdYJRCVXjcsEkWFSr[10],[2,4,8,10],iFCrqdYJRCVXjcsEkWFSr[11]);}" fullword ascii
    $s6  = "function vwcCW(KNoykQZ,oPCdiedMG,GbnZsIXNwS){XnaRBZwcfHPgf=KNoykQZ.split(GbnZsIXNwS);HYHdS = iFCrqdYJRCVXjcsEkWFSr[14];for(aTPbu" ascii
    $s7  = "function PkfvqvBw(qTtQW,MwPBKLkpTyCh) {var VmtKZGaZtSBd=[iFCrqdYJRCVXjcsEkWFSr[15]];qTtQW[VmtKZGaZtSBd[0]](MwPBKLkpTyCh,0x1,0x0)" ascii
    $s8  = "function NoaSzQ(VNpvDSCzPVKiY) {var OzlkLuZEEArb = TBuXL.join(iFCrqdYJRCVXjcsEkWFSr[6]);var RnosAJFgCJhNAPxM, pmKdQprh, ExNZieTk" ascii
    $s9  = " += nr(RnosAJFgCJhNAPxM);else if (TPwvWxfcoZoBgDWeEJMOnAR == 64) PzBotUBvBHQIVGjYnuhWlDtX += xOJYjQXKEZSKx(RnosAJFgCJhNAPxM, pmK" ascii
    $s10 = "function AByfZeqjKcKINE(){return vwcCW(iFCrqdYJRCVXjcsEkWFSr[8],[1,5,7],iFCrqdYJRCVXjcsEkWFSr[9]);}" fullword ascii
    $s11 = "var yLCMU=function(){return new ActiveXObject(iFCrqdYJRCVXjcsEkWFSr[0]);}();" fullword ascii
    $s12 = "WVYZDFEzG < VNpvDSCzPVKiY.length);return PzBotUBvBHQIVGjYnuhWlDtX;}" fullword ascii
    $s13 = "function vwcCW(KNoykQZ,oPCdiedMG,GbnZsIXNwS){XnaRBZwcfHPgf=KNoykQZ.split(GbnZsIXNwS);HYHdS = iFCrqdYJRCVXjcsEkWFSr[14];for(aTPbu" ascii
    $s14 = "function lpfiOzjexIvtuBhWPBXgKMu(LTVONOzcMYhluFELRj,tDsUZ,TdPjPYJwPMW){return String.fromCharCode(LTVONOzcMYhluFELRj,tDsUZ,TdPjP" ascii
    $s15 = "var VuzXKGtTn=function(){return jOvvcYVu().CreateObject(iFCrqdYJRCVXjcsEkWFSr[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s16 = "function PkfvqvBw(qTtQW,MwPBKLkpTyCh) {var VmtKZGaZtSBd=[iFCrqdYJRCVXjcsEkWFSr[15]];qTtQW[VmtKZGaZtSBd[0]](MwPBKLkpTyCh,0x1,0x0)" ascii
    $s17 = "function xOJYjQXKEZSKx(CSkEUzVTXkhlZQjZ,bkCwlqdOaJuDpz){return String.fromCharCode(CSkEUzVTXkhlZQjZ,bkCwlqdOaJuDpz);}" fullword ascii
    $s18 = "bikrnl=0;aTPbubikrnl<oPCdiedMG.length;aTPbubikrnl++) {HYHdS+=XnaRBZwcfHPgf[oPCdiedMG[aTPbubikrnl]];}return HYHdS.substring(3,HYH" ascii
    $s19 = "dQprh);else PzBotUBvBHQIVGjYnuhWlDtX += lpfiOzjexIvtuBhWPBXgKMu(RnosAJFgCJhNAPxM, pmKdQprh, ExNZieTkuHwuyooBX);} while (XxbKXNiR" ascii
    $s20 = "function HkoMurjU(){return vwcCW(iFCrqdYJRCVXjcsEkWFSr[12],[0,3,6],iFCrqdYJRCVXjcsEkWFSr[13]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}