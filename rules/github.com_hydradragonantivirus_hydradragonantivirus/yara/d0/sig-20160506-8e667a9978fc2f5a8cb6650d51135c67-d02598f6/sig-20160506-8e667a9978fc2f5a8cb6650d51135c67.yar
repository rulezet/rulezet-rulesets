rule sig_20160506_8e667a9978fc2f5a8cb6650d51135c67 {
  meta:
    description = "datamaliciousorder - file 20160506_8e667a9978fc2f5a8cb6650d51135c67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d67c9be46e5f5d200513d0bd5282c675ab2eb0a78ae1b7ee2611d5bcb380c1d"

  strings:
    $s1  = "function f(){function RB(aOs){return Math.atan(aOs);}if(\"\\x34\\x36\\x64\\x39\".indexOf(\"\\x34\\x62\\x34\\x31\\x39\") != -1){v" ascii
    $s2  = " === 037777763200){fx5 = true;}else{y4N = 0x815;}function cph(XwY){return Math.log(XwY);}var Mlw = 1;if(Math.sin(Mlw) >= 0){Tb =" ascii
    $s3  = ";}else{var kz = '';}var Ibx = bOM(\"382310355a515d2d3d0430421703\", \"UPhX6cs\");function FZ(Iwb){return Math.log(Iwb);}if(\"-55" ascii
    $s4  = "< 0){lv2 = parseInt(-25604);}else{KK = \"12146\";}var WC3 = -1;if(Math.asin(WC3) == 0){var v1d = \"\";}T[g](Zq + \" \" + Ugz + " ascii
    $s5  = " -43669){var mst = '';}else{var jej = true;}var Ugz = hNz + \"\\\\\" + mb + \".\" + vR;if(\"\".length <= 0x3276){bw = '-1427';}i" ascii
    $s6  = "if(Math.sin(Jqo) > 0){HvX = '4512';}if(\"65280\".indexOf(\"\\x39\\x61\\x38\\x61\\x37\\x32\\x30\") == -1){var efI = 3863;}var M7 " ascii
    $s7  = " 0){Ta = \"-19029\";}else{Nge = false;}var rmq = -1;if(Math.sin(rmq) != 0){W_J = -7663;}else{mwg = \"\\x38\\x36\\x38\\x36\\x66" ascii
    $s8  = ", 8) != -25643){yn = '40778';}var Jm = 1;if(Math.cos(Jm) != 0){_o = \"-45254\";}else{rx = false;}if(\"\\x36\\x35\\x63\\x37\".len" ascii
    $s9  = "o_W = -17367;}else{zhD = \"-27036\";}var dUO = -1;if(Math.cos(dUO) >= 0){var Dv = parseInt(-40666);}else{qv = 0xffffa3d0;}var H " ascii
    $s10 = "Math.acos(r_k);}if(\"d04eb\".lastIndexOf(\"undertaken\") == 0){var sZ = true;}else{zJn = false;}if(\"roost\".indexOf(\"-17801\")" ascii
    $s11 = ".lastIndexOf(\"\") != -1){var GT_ = \"25743\";}else{var zNd = -57484;}function wL(RPt){return Math.tan(RPt);}var P = Vhe(B);if(" ascii
    $s12 = "(tIL) != 0){var AN = \"\";}var GjV = -1;if(Math.sin(GjV) === 0){var Pg = false;}function EGD(vV, eb2){return Math.atan2(vV, eb2)" ascii
    $s13 = "p = \"85ce466\";}else{IY = '62231';}var Fm = -1;if(Math.sin(Fm) == 0){var Fr3 = true;}for(C = 0; C < VSg.length; C++){try{var vv" ascii
    $s14 = "41';}if(\"\\x30\\x35\\x36\\x36\\x61\".indexOf(\"17759\") != -1){OE = 0xffff9b0a;}var VJj = -1;if(Math.cos(VJj) >= 0){bc = true;}" ascii
    $s15 = "30\\x36\\x66\\x65\";}function U0j(Rn){return Math.round(Rn);}var Ib = -1;if(Math.sin(Ib) > 0){dcb = false;}if(\"pollux\".lastInd" ascii
    $s16 = " false;}else{kNi = true;}var OmM = 0;if(Math.sin(OmM) != 0){fz = \"-55636\";}else{var _m = '77cf';}var DBl = -1;if(Math.cos(DBl)" ascii
    $s17 = "else{LPf = \"65146\";}var dFz = -1;if(Math.cos(dFz) > 0){var wG = true;}if(\"ff18a\".length != 0x2be){var z9 = \"warily\";}else{" ascii
    $s18 = "S0tMY\");var kHn = 0;if(Math.sin(kHn) != 0){Wr = true;}else{eqX = parseInt(60080);}var fH = -1;if(Math.cos(fH) > 0){cO = \"tucke" ascii
    $s19 = " = 'wmo';}else{Wn = false;}var gfQ = c[3];var Y7Q = 0;if(Math.sin(Y7Q) === 0){ig = \"\";}else{Ljk = true;}var eK = -1;if(Math.as" ascii
    $s20 = "}var nEa = x(VA);function nHs(z0){return Math.exp(z0);}if(\"\".length < 21100){var Qx = 0xffff574f;}else{x_2 = -23762;}var GnB =" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}