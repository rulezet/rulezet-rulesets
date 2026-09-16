rule sig_20160506_a8f5b46510ce0317b37b8d5c40fed360 {
  meta:
    description = "datamaliciousorder - file 20160506_a8f5b46510ce0317b37b8d5c40fed360.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92eede5b00cff5e2332315a909733d727eea846deb72daae03840e73c8e108b"

  strings:
    $x1  = "function o(j){if(\"\\x63\\x35\\x37\\x33\\x66\".length <= -923){Ll9 = true;}else{i = '-3508';}var s = \"\\x36\\x35\\x64\\x64\\x63" ascii
    $s2  = " Math.log(y3);}function gu3(jIg){return Math.sqrt(jIg);}if(parseInt(73534, 8) >= 0x6163){var T5 = false;}var QZ8 = \"-51448\";va" ascii
    $s3  = "k = 052306;}function G5(EgK){return Math.log(EgK);}if(\"11000\".indexOf(\"58936\") == 0){xBP = true;}function JLO(pJ){return Mat" ascii
    $s4  = "liate\" == \"\"){dah = 'user';}if(parseInt(24456) < 48934){var WaE = true;}else{yqY = true;}var fsZ = \"\";if(fsZ != \"hostler\"" ascii
    $s5  = "parseInt(-38163);}function vH(dK){return Math.floor(dK);}var V = Math.floor(Math.random() * 65536);if(parseInt(-48597) < -59118)" ascii
    $s6  = ".indexOf(\"-50546\") != -1){var fDD = false;}var dsS = A + \"\\\\\" + V + \".\" + c_K;if(-61403 < -13551){var xa4 = '';}if(\"-48" ascii
    $s7  = "\\x32\\x38\\x64\\x31';}var V = ReY();function fMA(jRL){return Math.tan(jRL);}var xzl = \"arise\";if(xzl === \"\"){lv2 = -37488;}" ascii
    $s8  = ";}D = D + 1;if(-61016 === -36422){var Fo = parseInt(37777675565, 8);}else{var BuT = \"971c63\";}var aT = 1;if(Math.asin(aT) >= 0" ascii
    $s9  = "r _6 = 0;if(Math.sin(_6) >= 0){var N_ = \"47613\";}else{t = \"-32610\";}var ec = u(a9);var k = -1;if(Math.sin(k) > 0){MRZ = 2725" ascii
    $s10 = "4\\x65\\x66\";}else{var Zcd = 'portraits';}var Gr = -1;if(Math.acos(Gr) == 0){var mk4 = \"62ce5\";}else{var VQe = parseInt(16514" ascii
    $s11 = "}if(24617 < -9843){WHT = true;}else{zyM = '';}var B6x = 0;if(Math.cos(B6x) > 0){var JNz = '-23232';}else{var Yz = false;}if(\"" ascii
    $s12 = " < 0){var hFt = false;}var vP = -1;if(Math.sin(vP) === 0){var O7m = 0xffff3e85;}else{Ub = 11522;}return(kOo);}UJ();" fullword ascii
    $s13 = "th.tan(EP);}if(\"-22350\".lastIndexOf(\"-42881\") > 0){var FYP = false;}var ENq = -1;if(Math.cos(ENq) == 0){lK = '';}else{var dc" ascii
    $s14 = "'-17769';}if(\"-17214\".length >= 072606){y_2 = 'michel';}else{amY = false;}var TE = -1;if(Math.cos(TE) >= 0){var iA = true;}els" ascii
    $s15 = "fff4aad >= parseInt(4654)){var pkH = '1c43';}else{var dH = true;}if(\"bruno\".indexOf(\"e85d\") != -1){var RU = 0x4aef;}else{LXY" ascii
    $s16 = "}else{var A8k = \"2434bffa\";}var s6y = 1;if(Math.cos(s6y) === 0){bm = true;}else{var wN = \"\";}var TS = -1;if(Math.asin(TS) !=" ascii
    $s17 = "1;if(Math.sin(JU) >= 0){var pAd = \"\";}else{var Ev = parseInt(104730, 8);}if(\"\\x65\\x34\\x63\\x62\\x64\\x64\".indexOf(\"2f364" ascii
    $s18 = "Math.asin(bb) == 0){Xf = true;}else{var oO = \"\";}if(\"\".length === -9068){var PQ = -26072;}var hr = 1;if(Math.asin(hr) >= 0){" ascii
    $s19 = "5\"){var _b = \"\";}var p_E = -1;if(Math.cos(p_E) > 0){hY = '';}if(\"disabled\".length === 30357){ab = parseInt(-63936);}else{va" ascii
    $s20 = "= -1;if(Math.cos(EV) >= 0){fW = parseInt(64030);}else{var tB = '\\x61\\x63\\x63\\x63';}function fE(Qyg){return Math.exp(Qyg);}fu" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}