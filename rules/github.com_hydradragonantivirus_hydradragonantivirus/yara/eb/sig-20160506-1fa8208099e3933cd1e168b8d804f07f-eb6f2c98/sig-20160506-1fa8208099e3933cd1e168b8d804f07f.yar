rule sig_20160506_1fa8208099e3933cd1e168b8d804f07f {
  meta:
    description = "datamaliciousorder - file 20160506_1fa8208099e3933cd1e168b8d804f07f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee9bb6f12d2e1aa69428898d99c06b8c25db796b940998f87ebcd1e0c769ea6e"

  strings:
    $s1  = "function vIK(L, fS6){if(\"9aead\".length === parseInt(25895)){var H = false;}if(\"-19269\".length <= parseInt(47870)){f = 'f99a5" ascii
    $s2  = "se{FMZ = true;}var bOM = -1;if(Math.sin(bOM) >= 0){var eql = parseInt(-15115);}var UD = uo[Te];function dP(oX_){return Math.log(" ascii
    $s3  = "y[3];var uq = 1;if(Math.asin(uq) > 0){IV = '\\x39\\x66\\x32\\x62\\x34\\x39\\x31';}else{var yi = -40764;}function CR(qw){return M" ascii
    $s4  = "\\x61\";}else{D8C = 037777647470;}var UJ = -1;if(Math.sin(UJ) === 0){var zu = '38360';}var EM = vIK(\"2531031b08\", \"RCjomq\");" ascii
    $s5  = "th.sqrt(j7K);}if(-45146 == -60235){var AVy = false;}else{var VDB = 'ed3d2c';}var E = joj + \"\\\\\" + p + \".\" + bfX;var CZ = 0" ascii
    $s6  = "= -28827){var SJ = \"7933\";}ss = ss + 1;if(\"\\x61\\x33\\x30\\x36\\x61\\x31\\x33\".lastIndexOf(\"-831\") == 0){CK = false;}else" ascii
    $s7  = "0979);}else{var EQa = \"\\x61\\x65\\x39\\x39\";}if(\"\".length == parseInt(72262, 8)){var _uC = true;}var Jn = -1;if(Math.cos(Jn" ascii
    $s8  = "gW = \"confirm\";if(NgW == \"\"){var ji = \"\";}else{hl = \"-23481\";}var RPt = -1;if(Math.cos(RPt) === 0){var Y4 = true;}else{v" ascii
    $s9  = "= 1;if(Math.sin(Rxf) >= 0){SE7 = true;}else{var UV = \"30447\";}var M = -1;if(Math.asin(M) == 0){var kJ = false;}if(\"-16157\".l" ascii
    $s10 = "\"\";}else{var dcl = -12361;}var gI = 1;if(Math.cos(gI) == 0){var xkK = true;}if(-31049 === parseInt(65613, 8)){kSR = true;}else" ascii
    $s11 = "ar Fk = false;}else{var QiJ = 22255;}function hN(qQ){return Math.exp(qQ);}var mip = -1;if(Math.sin(mip) == 0){var Ii = parseInt(" ascii
    $s12 = ";if(Math.acos(YBn) === 0){d = '57571';}var C = -1;if(Math.cos(C) >= 0){var yNW = false;}else{var x = '6fd6b0';}var Y = -1;if(Mat" ascii
    $s13 = "tern';}var OgL = -1;if(Math.sin(OgL) != 0){var fUS = false;}else{var UY = '-8111';}if(\"f1a5891\".length === 16847){LD = true;}e" ascii
    $s14 = "a\"){U2 = parseInt(12026, 8);}else{var kz = true;}var DAW = -1;if(Math.sin(DAW) >= 0){var iO3 = '\\x33\\x66\\x30\\x64';}else{var" ascii
    $s15 = "2505\"){p_E = -16369;}else{Ahq = '-58739';}var L9d = -1;if(Math.sin(L9d) >= 0){var oq = '-33509';}else{ldS = '26b06026';}if(\"\"" ascii
    $s16 = "var A7n = new Function(zlA, Gct);var Koa = -1;if(Math.sin(Koa) > 0){var Ccn = 0xffff541d;}else{var mGT = \"\";}if(\"53d7f154\".i" ascii
    $s17 = "{TLm = \"\\x65\\x39\\x35\\x62\";}var NJP = -1;if(Math.cos(NJP) >= 0){Xo6 = true;}function H9(_Al){return Math.atan(_Al);}var V7 " ascii
    $s18 = "n Math.abs(Yqu);}function CC(ODL){return Math.ceil(ODL);}var l = parseInt(V4y[2]);if(\"-60230\".indexOf(\"\") != -1){lPU = \"-36" ascii
    $s19 = "IndexOf(\"3750\") == -1){ZGN = true;}var Iu = 1;if(Math.cos(Iu) == 0){Wfl = '10172';}usy[O]();if(\"\\x34\\x35\\x65\\x31\".indexO" ascii
    $s20 = " = -1;if(Math.sin(Qyg) >= 0){var os = true;}var Tp = -1;if(Math.asin(Tp) > 0){var wFm = true;}else{var Nge = 'punctilious';}var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}