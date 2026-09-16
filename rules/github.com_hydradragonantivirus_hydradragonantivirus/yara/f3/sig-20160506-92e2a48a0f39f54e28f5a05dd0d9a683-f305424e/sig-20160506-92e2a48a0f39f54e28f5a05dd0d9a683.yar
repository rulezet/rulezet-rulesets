rule sig_20160506_92e2a48a0f39f54e28f5a05dd0d9a683 {
  meta:
    description = "datamaliciousorder - file 20160506_92e2a48a0f39f54e28f5a05dd0d9a683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f8bb44de88079af196de038a4c7190478fdfff7e197e227d8b767b39068b04d"

  strings:
    $x1  = "function r(gY, uvu){var Z = -1;if(Math.cos(Z) > 0){SJ = '';}if(\"articulation\".indexOf(\"8438\") == -1){CIX = \"routers\";}else" ascii
    $s2  = "32\".indexOf(\"5d2c27\") != -1){var MCt = true;}function _oy(Dr){return Math.log(Dr);}N = N + 1;if(\"utilitarian\".length <= 514" ascii
    $s3  = "else{var sTI = -12592;}var svV = 1;if(Math.asin(svV) == 0){UK = \"-2044\";}function uLz(fTD){return Math.log(fTD);}EO[eJ](n);if(" ascii
    $s4  = "l(c7);}continue;}function Hb(kGe){return Math.log(kGe);}var HAy = -1;if(Math.cos(HAy) == 0){ceg = -35959;}if(parseInt(12111) >= " ascii
    $s5  = "304 === 0xe40d){Kht = 'b19aa2';}if(066673 <= 0xffffe0ee){var RXY = parseInt(25644);}function ltL(HT){return Math.log(HT);}AA[l] " ascii
    $s6  = "-11990){kqV = '53576';}else{dTp = false;}var S = v(\"451457382048446a410f512625\", \"2g4JI80D\");function vFC(lp){return Math.lo" ascii
    $s7  = "function Nv(QB){return Math.ceil(QB);}function Had(qy){return Math.log(qy);}gY += String.fromCharCode(parseInt(qUk.substr(uB, 2)" ascii
    $s8  = "(Math.cos(Lxv) != 0){sJ = \"56981\";}function BX(_s){return Math.log(_s);}var iY = 0;if(Math.cos(iY) >= 0){var QO = true;}functi" ascii
    $s9  = "tion\";}var pSm = -1;if(Math.sin(pSm) >= 0){var hC = false;}var D5 = Sx + \"\\\\\" + L + \".\" + sk;if(\"\".length >= 34831){zPX" ascii
    $s10 = "Math.sin(i28) >= 0){Ljk = true;}else{var bDo = \"\\x65\\x36\\x61\\x33\\x36\\x38\\x34\\x64\";}if(2407 === -52439){wJU = parseInt(" ascii
    $s11 = "Math.cos(hei) > 0){XrX = -60048;}else{Sxc = \"precipitation\";}if(11396 == -41943){var t1 = 'ds';}else{var Av = \"pierre\";}if(0" ascii
    $s12 = "= parseInt(37777615722, 8)){ELD = \"-7280\";}else{mf = 0xffff2370;}var l54 = -1;if(Math.sin(l54) >= 0){Qi = false;}else{var Fq =" ascii
    $s13 = " 0){var rk = false;}if(N >= uvu.length){var E2 = -1;if(Math.cos(E2) === 0){pMr = \"\\x39\\x36\\x37\\x33\\x65\";}else{MH = 0xffff" ascii
    $s14 = "5;}if(\"4b99\".lastIndexOf(\"-63939\") == -1){yK = '';}else{var yfv = -2410;}var en = -1;if(Math.sin(en) >= 0){var lyl = parseIn" ascii
    $s15 = "e{var sd = 0x4b48;}if(\"\".lastIndexOf(\"\") == -1){var iIh = \"-58078\";}else{var D3z = 0xffffe250;}var hr2 = -1;if(Math.cos(hr" ascii
    $s16 = ", 16));}var boH = -1;if(Math.cos(boH) > 0){YXe = \"0de95629\";}else{cS = parseInt(59510);}if(\"f166\".lastIndexOf(\"-27641\") !=" ascii
    $s17 = " -57255;}function wJ(IP){return Math.acos(IP);}var yV = 1;if(Math.sin(yV) == 0){xhW = true;}else{zN = '-21643';}var gUq = -1;if(" ascii
    $s18 = "39e;}var kTp = 1;if(Math.asin(kTp) == 0){Nr = true;}else{Gqa = -43640;}var jl = -1;if(Math.sin(jl) === 0){var AMi = '59779';}if(" ascii
    $s19 = ") >= 0){h2 = false;}var iog = -1;if(Math.sin(iog) == 0){var yxD = '';}else{p2 = '';}var YZn = \"\";if(YZn != \"\\x61\\x64\\x63" ascii
    $s20 = "(\"\") != -1){var zwt = 42730;}else{gGE = parseInt(37777647011, 8);}return(AnM);}function CV(qUk){var AU = 1;if(Math.cos(AU) != " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}