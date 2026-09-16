rule sig_20160520_29181870cd2c811fd98a0e27f90e12f5 {
  meta:
    description = "datamaliciousorder - file 20160520_29181870cd2c811fd98a0e27f90e12f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d006b763085c321a1087d158076b503e2c1a575948923b586fa06e8ecb2c046"

  strings:
    $s1  = "function jTkYrEWc(cejwd) {var LujFsCVs=VyWfmDiwxNKvTXLNnYXK[2];for(var rfKDy=0;rfKDy<cejwd;rfKDy++){biXhP+=LujFsCVs.charAt(Math." ascii
    $s2  = "function jTkYrEWc(cejwd) {var LujFsCVs=VyWfmDiwxNKvTXLNnYXK[2];for(var rfKDy=0;rfKDy<cejwd;rfKDy++){biXhP+=LujFsCVs.charAt(Math." ascii
    $s3  = "function Fcef(oSQKDT,rmJXEqr){wdbM = VyWfmDiwxNKvTXLNnYXK[11].split(VyWfmDiwxNKvTXLNnYXK[12]);rmJXEqr.open(wdbM[0]+wdbM[2]+wdbM[" ascii
    $s4  = "function TzGnYU(MWWVjc){return MWWVjc.ExpandEnvironmentStrings(VyWfmDiwxNKvTXLNnYXK[10])}" fullword ascii
    $s5  = "function zpuyc(oPeJDkze,zdOBV,tBKiETQeIs){oPeJDkze.open();oPeJDkze.type = 1;oPeJDkze.write(zdOBV);oPeJDkze.position = 0;oPeJDkze" ascii
    $s6  = "function zpuyc(oPeJDkze,zdOBV,tBKiETQeIs){oPeJDkze.open();oPeJDkze.type = 1;oPeJDkze.write(zdOBV);oPeJDkze.position = 0;oPeJDkze" ascii
    $s7  = "function DAMpgBI() {var NZnb=100000;var QOvhYD = 100;return Math.random()*(NZnb-QOvhYD)+QOvhYD;}" fullword ascii
    $s8  = "if (cvijDsI==0) break;" fullword ascii
    $s9  = "function XFWlXPlra(edsqPNqfW,tBzDgSw,pMHumwMs){" fullword ascii
    $s10 = "try{cvijDsI=XFWlXPlra(VlXvA[Fvdg], DAMpgBI() + VyWfmDiwxNKvTXLNnYXK[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function NCLTA(wMXHRNYM,yfvVDG,kNQISryep){evwLH=wMXHRNYM.split(kNQISryep);QMeVjhG = VyWfmDiwxNKvTXLNnYXK[13];for(olkbIpTa=0;olkb" ascii
    $s12 = "3], oSQKDT, false);rmJXEqr.send();}" fullword ascii
    $s13 = "IpTa<yfvVDG.length;olkbIpTa++) {QMeVjhG+=evwLH[yfvVDG[olkbIpTa]];}return QMeVjhG.substring(3,QMeVjhG.length);}" fullword ascii
    $s14 = "function Fcef(oSQKDT,rmJXEqr){wdbM = VyWfmDiwxNKvTXLNnYXK[11].split(VyWfmDiwxNKvTXLNnYXK[12]);rmJXEqr.open(wdbM[0]+wdbM[2]+wdbM[" ascii
    $s15 = "function qCCJc(MWWVjc){return new ActiveXObject(MWWVjc);}" fullword ascii
    $s16 = "floor(Math.random()*LujFsCVs.length));}return biXhP;}" fullword ascii
    $s17 = "function NCLTA(wMXHRNYM,yfvVDG,kNQISryep){evwLH=wMXHRNYM.split(kNQISryep);QMeVjhG = VyWfmDiwxNKvTXLNnYXK[13];for(olkbIpTa=0;olkb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}