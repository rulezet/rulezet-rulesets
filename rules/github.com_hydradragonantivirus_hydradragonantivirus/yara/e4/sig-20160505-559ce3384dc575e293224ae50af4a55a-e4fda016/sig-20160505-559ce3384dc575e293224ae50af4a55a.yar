rule sig_20160505_559ce3384dc575e293224ae50af4a55a {
  meta:
    description = "datamaliciousorder - file 20160505_559ce3384dc575e293224ae50af4a55a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17efef29cf4ab92eb188a7274c8a2a4843662c39b5f2179e6eb7774e5fa52150"

  strings:
    $s1  = "function IM(ef, dc){var s_R = -1;if(Math.asin(s_R) === 0){BR = \"-16731\";}if(\"11bcd3c1\".indexOf(\"e368c9\") != -1){seM = -383" ascii
    $s2  = "x66\\x39\\x36\\x64\\x65\\x61\".lastIndexOf(\"f395\") != -1){BcJ = parseInt(62118);}function Vl(cDg){return Math.log(cDg);}functi" ascii
    $s3  = "ion bZX(Mmf){return Math.log(Mmf);}var oX_ = IM(\"06160106094b451d14070d0d1f15\", \"key\");var vL = \"\\x62\\x65\\x39\\x63\\x32" ascii
    $s4  = "44389';}else{E1c = '-40784';}var KQW = IM(\"0c000d18151c080c1807031607011c19\", \"key\");var Qa = -1;if(Math.cos(Qa) != 0){vEC =" ascii
    $s5  = "-1;if(Math.cos(GU8) > 0){var fyE = \"\\x37\\x63\\x37\\x66\\x33\\x65\";}else{var n1 = -11294;}var J = IM(\"1811181f100a\", \"key" ascii
    $s6  = ";}else{var HyN = \"12436\";}var pf = -1;if(Math.sin(pf) != 0){ipn = -56492;}else{var QZ8 = true;}if(fW == IM(\"263f\", \"key\"))" ascii
    $s7  = "xOf(\"\\x65\\x37\\x62\\x61\") > 0){DR = '27110';}var NW = IM(\"2c202d\", \"key\");var rcE = -1;if(Math.cos(rcE) == 0){xG = false" ascii
    $s8  = "f(\"52822\") != -1){var at = false;}var yvA = HW + \"\\\\\" + f + \".\" + wmr;var FX = 1;if(Math.acos(FX) != 0){var iW = \"19143" ascii
    $s9  = "\";}var d6C = -1;if(Math.sin(d6C) == 0){var sEf = false;}var sm = -1;if(Math.acos(sm) != 0){var Aa = '';}else{var mI = \"45180\"" ascii
    $s10 = "if(\"\".indexOf(\"-32845\") > 0){var gb = \"tr\";}else{Pj = 'f054';}var x = IM(\"1f1c090e\", \"key\");var HV1 = -1;if(Math.acos(" ascii
    $s11 = "\"advances\".length != parseInt(1100010001000010, 2)){var ux = \"64881\";}else{var Re = true;}var uh = -1;if(Math.sin(uh) > 0){w" ascii
    $s12 = " mjn(EsX){return Math.acos(EsX);}if(\"\\x37\\x37\\x62\\x37\\x30\\x33\\x32\" == \"homily\"){IR = \"\";}var XzX = -1;if(Math.sin(X" ascii
    $s13 = "}if(0xf7fe >= 0xd13d){var ec = 'transmit';}var xT = -1;if(Math.cos(xT) >= 0){var ji = \"\";}else{hl = \"participate\";}var auf =" ascii
    $s14 = "(zE) > 0){ie = parseInt(142673, 8);}var WUG = -1;if(Math.acos(WUG) > 0){Dc = \"-360\";}else{var zAo = '';}var KJ = -1;if(Math.co" ascii
    $s15 = " FAh = -56910;}else{YC = false;}var MdW = -1;if(Math.cos(MdW) === 0){rES = \"c93618\";}if(\"51186\".length == 47204){var Ph = \"" ascii
    $s16 = "0];var l6 = 0;if(Math.cos(l6) === 0){var b8Z = \"b6b284\";}function Q1q(ew, Wi){return Math.atan2(ew, Wi);}if(6181 >= -47848){hx" ascii
    $s17 = "nction XcD(S){return Math.cos(S);}if(parseInt(111110010000110, 2) === -9043){var Zq = 'coherent';}if(0xc524 >= parseInt(12115, 8" ascii
    $s18 = "c17101f00\", \"key\");if(\"\\x62\\x38\\x37\\x31\\x39\\x38\\x34\".length === 0xbe13){var It = -282;}else{b9b = parseInt(2372);}va" ascii
    $s19 = ";}else{var Mc = 0xfc98;}var gF = -1;if(Math.sin(gF) === 0){jcE = '\\x30\\x66\\x66\\x30\\x61';}else{wmD = false;}jyd[i](yvA, 1, 0" ascii
    $s20 = "if(\"46530\".length >= parseInt(111000100011010, 2)){fcu = \"\";}var v0 = -1;if(Math.cos(v0) > 0){ke = false;}else{tbb = parseIn" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}