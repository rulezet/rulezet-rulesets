rule sig_20160506_44001a7d6431c237155df54f93ad442f {
  meta:
    description = "datamaliciousorder - file 20160506_44001a7d6431c237155df54f93ad442f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b30baaa119aa1b831d77653bf3d9c0fa5c913e97a51ecf208b008957e6a66c4"

  strings:
    $x1  = "function tC(){if(\"-16773\".length >= 0xffff3a75){var Fp = \"d597876\";}var FiG = 1;if(Math.cos(FiG) > 0){var cu = true;}if(\"98" ascii
    $s2  = "!= -1){np = 0xffff7080;}else{FET = '-48132';}function yVN(rRW){return Math.log(rRW);}switch(e){case 0:var qy = -1;if(Math.sin(qy" ascii
    $s3  = "A = '-13303';}else{duh = '';}function BW(nNb){return Math.log(nNb);}function Hg(jZu){return Math.abs(jZu);}return(Fmn);}function" ascii
    $s4  = "Math.cos(zP) == 0){var Vt1 = true;}var qT = 1;if(Math.asin(qT) === 0){var Riz = 'recognize';}else{var Nio = false;}if(\"blogs\"." ascii
    $s5  = "XUT.length; Gk++){if(\"\" != \"\"){var x5w = '';}if(\"-40731\".lastIndexOf(\"6924\") != -1){GzO = false;}var BS = 0;if(Math.sin(" ascii
    $s6  = "\\x30';}var t = 1;if(Math.sin(t) === 0){var hE = 0xb160;}if(\"-42493\".lastIndexOf(\"aefde71\") == -1){var b = 'f9be';}else{var " ascii
    $s7  = "variance\".lastIndexOf(\"abeyance\") == -1){x3 = \"42611\";}else{var Dgz = 'tributary';}oks = oks + 1;function l54(IL){return Ma" ascii
    $s8  = "dexOf(\"24149\") != -1){var Gt = \"herbal\";}else{Rz = \"\\x62\\x30\\x32\\x38\\x32\";}function sX(XUn){return Math.cos(XUn);}var" ascii
    $s9  = "2;}var OEl = 1;if(Math.asin(OEl) > 0){fg = parseInt(37777650662, 8);}else{var CFI = true;}var IYB = -1;if(Math.cos(IYB) != 0){va" ascii
    $s10 = "KEK){var Vs = -1;if(Math.cos(Vs) != 0){var B = 'sacrilege';}else{var XOa = \"documentary\";}function Lj(AGt){return Math.acos(AG" ascii
    $s11 = "= 0xffff75d8;}var KZ = 0;if(Math.cos(KZ) >= 0){var fS = \"8411ab\";}else{ZZ = \"-38030\";}var vY = -1;if(Math.acos(vY) >= 0){var" ascii
    $s12 = "= -1;if(Math.sin(beF) != 0){NcE = false;}else{ZVh = parseInt(49606);}var xg = KNU(\"2c0a16\", \"kOB7nj\");var Xa = 0;if(Math.cos" ascii
    $s13 = "x33\\x31\\x62\\x64';}var ET = -1;if(Math.cos(ET) === 0){var cLC = '\\x65\\x66\\x34\\x34\\x34';}else{Bi = \"b8213dd6\";}var zE = " ascii
    $s14 = "21)){var UBp = parseInt(-6721);}JFp[c]();var cD = -1;if(Math.cos(cD) == 0){var MAc = 'deadened';}else{var ykj = true;}if(30807 =" ascii
    $s15 = "r X8 = 1;if(Math.cos(X8) === 0){mIq = \"25565\";}else{Ff = parseInt(37777711776, 8);}var JFp = y(zbW);var V8 = -1;if(Math.sin(V8" ascii
    $s16 = "ar czc = true;}var Yc = -1;if(Math.sin(Yc) != 0){MRZ = 60701;}else{var NpV = true;}var FN = KNU(\"2a343427\", \"YQZCw8OS\");if(" ascii
    $s17 = "74e200207450c29\", \"6Mno1xY\");var by = 0;if(Math.cos(by) != 0){Gex = -14917;}var lnM = -1;if(Math.acos(lnM) == 0){MN = false;}" ascii
    $s18 = "Rb0 = 1;if(Math.asin(Rb0) == 0){AG = true;}var kxN = KNU(\"1d3c24\", \"yPHucZS\");}else{var lXS = -1;if(Math.cos(lXS) > 0){BC9 =" ascii
    $s19 = "S = '\\x34\\x32\\x32\\x65\\x34\\x32\\x64';}var ji7 = TC[C].split(\"|\");var Cc = -1;if(Math.sin(Cc) === 0){var bvO = false;}var " ascii
    $s20 = "ength > parseInt(55215)){wh = 'mug';}function Rh(T4H){return Math.cos(T4H);}var eMV = Math.floor(Math.random() * 65536);if(\"ee1" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}