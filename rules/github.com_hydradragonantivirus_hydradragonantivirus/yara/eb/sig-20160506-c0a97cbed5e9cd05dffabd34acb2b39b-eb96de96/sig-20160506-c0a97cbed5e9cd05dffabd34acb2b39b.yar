rule sig_20160506_c0a97cbed5e9cd05dffabd34acb2b39b {
  meta:
    description = "datamaliciousorder - file 20160506_c0a97cbed5e9cd05dffabd34acb2b39b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfc8d45aaa64560705d0a146154a2869bd2821cbf043e737972ff0ef8557bdf6"

  strings:
    $x1  = "function Jp8(rf3){var q6 = 1;if(Math.sin(q6) == 0){var v0 = '';}else{V = '-15105';}if(\"\\x34\\x35\\x65\\x34\\x34\".length <= 03" ascii
    $s2  = "{return Math.log(GYJ);}P = P + 1;var Fq = 1;if(Math.cos(Fq) >= 0){QI = '-45977';}else{bwb = \"\";}var mpx = \"44562\";var TZ = " ascii
    $s3  = "PZr(syH){return Math.log(syH);}var ZBC = -1;if(Math.sin(ZBC) >= 0){iW = true;}if(-19216 < parseInt(37777661345, 8)){var yus = -5" ascii
    $s4  = "Math.sin(nQO) >= 0){var ks = 6130;}else{lE = parseInt(18652);}function pHQ(hkq){return Math.log(hkq);}if(\"-13326\".indexOf(\"45" ascii
    $s5  = "ath.sqrt(mqQ);}var cp = 0;if(Math.sin(cp) > 0){var i0 = false;}else{Uvs = true;}var DK = -1;if(Math.cos(DK) == 0){var o3S = '-25" ascii
    $s6  = " = true;}if(\"authors\".lastIndexOf(\"14f050\") > 0){Gzy = '-1972';}var yrC = -1;if(Math.sin(yrC) > 0){JvO = \"2480e640\";}else{" ascii
    $s7  = "w5S = \"-39955\";}var e = la(rf3, ju);var kzM = -1;if(Math.sin(kzM) === 0){var Kvh = \"907\";}else{var VK = 26210;}var OZR = 1;i" ascii
    $s8  = "h.acos(iY) != 0){var Rvg = true;}else{lPD = true;}var He = -1;if(Math.cos(He) > 0){var wC = '50352';}var n4 = 1;if(Math.asin(n4)" ascii
    $s9  = "if(VG == \"\\x62\\x63\\x32\\x36\\x34\"){D7M = \"-35298\";}else{jAb = 25289;}var TeC = -1;if(Math.cos(TeC) > 0){WtI = 0115362;}el" ascii
    $s10 = "{sDa = 'os';}var uu = -1;if(Math.cos(uu) == 0){DS4 = 'irs';}else{M5k = false;}var Df = f(sC);var wR3 = 1;if(Math.acos(wR3) >= 0)" ascii
    $s11 = "r yS = \"\";}var o6d = new Array();var rAp = -1;if(Math.cos(rAp) === 0){var sNN = true;}else{var iGC = '25721';}var iY = -1;if(M" ascii
    $s12 = "de(parseInt(rf3.substr(C, 2), 16));}var Op = 1;if(Math.cos(Op) > 0){H3 = true;}else{var hF = \"\";}if(\"\".length >= -54255){var" ascii
    $s13 = "wdh7GL\");function FM(eiN){return Math.sin(eiN);}var VUl = -1;if(Math.acos(VUl) === 0){AIE = \"nerve\";}else{LY = 0xffff6016;}va" ascii
    $s14 = "r nH = -1;if(Math.cos(nH) > 0){veO = '6037';}var QqG = -1;if(Math.cos(QqG) >= 0){bZ = '';}Df[M]();function eMU(Ew){return Math.a" ascii
    $s15 = "}else{HU = parseInt(-20430);}if(o6d[w] == 1){var DO = 0;if(Math.asin(DO) > 0){var YES = -31283;}var fjb = 0;if(Math.cos(fjb) >= " ascii
    $s16 = "l = true;}function s7N(RL){return Math.tan(RL);}var ytl = -1;if(Math.asin(ytl) === 0){NEM = '\\x61\\x65\\x30\\x38\\x37\\x33\\x34" ascii
    $s17 = "'-7927';}else{var T5 = true;}var cc = -1;if(Math.cos(cc) == 0){SG = true;}else{var Hdn = \"\\x33\\x32\\x65\\x32\";}var eAV = -1;" ascii
    $s18 = "gM) > 0){var NS = 28386;}if(\"-13864\".length > 037777606562){Igu = true;}var ppd = -1;if(Math.sin(ppd) === 0){JPR = '-43244';}e" ascii
    $s19 = "XH = -1;if(Math.asin(hXH) > 0){var ihU = 0xc1d;}var H = f(xv);function uN(Zl){return Math.sin(Zl);}var ryg = 0;if(Math.asin(ryg)" ascii
    $s20 = "O(\"2c223a\", \"kgnvPD\");var QB = 0;if(Math.sin(QB) === 0){var Bqa = true;}if(\"38145\".length > -23845){lX = 0xffffd72f;}var l" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}