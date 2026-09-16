rule sig_20160505_4618e23dd29a720cc518e7fcc366207d {
  meta:
    description = "datamaliciousorder - file 20160505_4618e23dd29a720cc518e7fcc366207d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfe4a7a131903dd6db7abf32dbfae05307d0086a80c76980acc7668c5ce5f45b"

  strings:
    $x1  = "function zcp(cu, hd){var BhS = -1;if(Math.acos(BhS) == 0){D_ = parseInt(-5912);}else{var r = false;}var Xvr = \"\\x61\\x32\\x32" ascii
    $s2  = "scellaneous\".length > -52227){wL = true;}else{var FPm = \"-6287\";}function hr2(l1){return Math.log(l1);}var Y = H();var zN = -" ascii
    $s3  = "ff8909){FH = parseInt(37777606240, 8);}var zdQ = 1;if(Math.cos(zdQ) === 0){var Ger = true;}function ECM(MyD){return Math.log(MyD" ascii
    $s4  = "151c080c1807031607011c19\", \"key\");if(\"roan\".length < -40726){Ibx = false;}else{cq = 'manoeuvring';}var Ua = -1;if(Math.cos(" ascii
    $s5  = "ath.sin(bOE) != 0){Qv = true;}if(\"pc\".length === -29230){var XX = true;}else{fSq = false;}function MM(pf6){return Math.acos(pf" ascii
    $s6  = "){r5G = false;}else{iZz = true;}var Hp_ = -1;if(Math.sin(Hp_) != 0){var HBe = parseInt(11111111111111111011010101000101, 2);}els" ascii
    $s7  = "!= 0xffff916c){var pW = 38545;}xNp = xNp + 1;if(\"sententious\".indexOf(\"d6137\") != -1){GlJ = parseInt(22400);}else{Qok = \"" ascii
    $s8  = "'';}else{var Eg = false;}var oV = 1;if(Math.sin(oV) > 0){DM8 = \"48d0\";}var C9 = q[u](2);var ux = -1;if(Math.asin(ux) != 0){var" ascii
    $s9  = " -1;if(Math.sin(xKr) === 0){var kV = \"\";}else{_C_ = \"warp\";}var xQ = zcp(\"18060b02150d020b1e45031007000a12160d0e0816090f1c0" ascii
    $s10 = "seInt(29790);}if(xNp >= hd.length){function O9e(Bu){return Math.atan(Bu);}var qI_ = -1;if(Math.sin(qI_) === 0){var aK = false;}e" ascii
    $s11 = "011101010, 2)){Qy = false;}var gq = -1;if(Math.cos(gq) == 0){xu = '-55670';}if(\"8f0a5\".lastIndexOf(\"\") > 0){var Px = 'd4a743" ascii
    $s12 = "sin(niS) == 0){var Vt1 = false;}var qT = -1;if(Math.cos(qT) > 0){var rW = '';}var GNu = eqX[V].substr(0, 2);var km7 = 1;if(Math." ascii
    $s13 = " \"key\");var Pb4 = -1;if(Math.acos(Pb4) == 0){var vr5 = true;}else{iC = true;}if(\"31957\".length == 22562){UQC = \"35e1d9\";}v" ascii
    $s14 = "f(Math.cos(za) != 0){bv = true;}else{var AEf = 3932;}if(\"-63969\".length < -46062){var gL = 0xb74b;}if(037777731266 != parseInt" ascii
    $s15 = "r Rfx = \"-4138\";}function _7Y(HNa){return Math.round(HNa);}var D8 = new Array();var oR = -1;if(Math.sin(oR) > 0){jn = \"\\x65" ascii
    $s16 = " = -1;if(Math.sin(PwS) > 0){var lG = parseInt(-51570);}var a4 = 1;if(Math.asin(a4) >= 0){BXO = \"23292\";}else{var l8 = '-40177'" ascii
    $s17 = "QU = false;}var H0e = -1;if(Math.sin(H0e) != 0){var wCp = 0xffff5bdd;}function eq(ZmB){return Math.atan(ZmB);}var jy = 1;if(Math" ascii
    $s18 = "rn Math.tan(bJ);}function dbY(kxz){return Math.ceil(kxz);}function Bqy(oYf){return Math.abs(oYf);}var zXi = -1;if(Math.asin(zXi)" ascii
    $s19 = "var q2I = 'ad2f559';}emG[kT] = 1;function K_j(CLe){return Math.exp(CLe);}if(\"35285a\".lastIndexOf(\"6965\") == -1){var eC = '-2" ascii
    $s20 = " = 1;if(Math.sin(dk) > 0){var vd = '-43457';}function yA(lfj){return Math.cos(lfj);}if(\"94858\".indexOf(\"541c\") == -1){MvB = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}