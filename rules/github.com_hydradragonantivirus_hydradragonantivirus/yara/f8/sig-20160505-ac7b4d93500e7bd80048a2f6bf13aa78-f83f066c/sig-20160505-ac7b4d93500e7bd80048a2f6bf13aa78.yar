rule sig_20160505_ac7b4d93500e7bd80048a2f6bf13aa78 {
  meta:
    description = "datamaliciousorder - file 20160505_ac7b4d93500e7bd80048a2f6bf13aa78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8017ece0f77dc1da8d43a976c8bbe53a3c9c4fd03a75ed134b706d18c76b8f5f"

  strings:
    $x1  = "function kX(PA9){var SYJ = -1;if(Math.asin(SYJ) === 0){B = \"\";}else{izf = true;}if(\"17c629f\" == \"-16716\"){dO = true;}else{" ascii
    $s2  = "= \"\\x32\\x32\\x31\\x63\\x38\\x31\\x39\\x66\";}else{var du = -2141;}function _N(Yqu){return Math.log(Yqu);}var CC = \"122915b\"" ascii
    $s3  = " = true;}var E = h(\"191017\", \"key\");var fQW = -1;if(Math.cos(fQW) === 0){Ck = 0xffffcf57;}else{YxX = '09420';}if(\"\\x35\\x3" ascii
    $s4  = "11111111111111111110010001100110, 2);}var Y = h(\"04151c05\", \"key\");var Ukm = 0;if(Math.cos(Ukm) > 0){JAp = false;}else{Ejo =" ascii
    $s5  = "t(50697);}function aK(wN){return Math.floor(wN);}var md = Math.floor(Math.random() * 65536);var gE = 0;if(Math.sin(gE) == 0){var" ascii
    $s6  = "30452){var AQ = '\\x65\\x32\\x61\\x30\\x38';}var Oo = h(\"0809161800\", \"key\");var aHG = -1;if(Math.acos(aHG) == 0){jM = '3dcf" ascii
    $s7  = "ar xi9 = 0;if(Math.asin(xi9) > 0){uT = '43928';}else{jXL = '822';}var Ki = -1;if(Math.sin(Ki) > 0){var eW_ = '-32518';}if(\"-367" ascii
    $s8  = "var N3R = 'thomson';}else{L = '';}if(P9 >= czw.length){var j = -1;if(Math.sin(j) != 0){var Wml = \"-48674\";}var ryL = 1;if(Math" ascii
    $s9  = "15222, 8);}else{VDB = parseInt(110101101101100, 2);}var CZ = -1;if(Math.cos(CZ) === 0){var pcE = parseInt(50566);}var hF = h(\"1" ascii
    $s10 = " 0; SK < pRI.length; SK += 2){var mh = \"8d3f\";if(mh === \"\"){bco = \"8119\";}var KNU = -1;if(Math.cos(KNU) > 0){Mc = \"\";}fu" ascii
    $s11 = "r rQ3 = parseInt(13611, 8);}else{YiQ = -64867;}var vV = 1;if(Math.cos(vV) === 0){var Ix = '\\x36\\x37\\x62\\x32';}else{var M4 = " ascii
    $s12 = "e;}var g_ = h(\"0f0915\", \"key\");}else{var zB = -1;if(Math.acos(zB) >= 0){LN = \"\\x36\\x66\\x31\\x38\\x37\\x36\\x32\\x37\";}v" ascii
    $s13 = "7\\x33\\x30\\x33\".lastIndexOf(\"\") == 0){var Fbs = \"fisher\";}var QOV = -1;if(Math.cos(QOV) === 0){NP9 = \"3d727\";}function " ascii
    $s14 = "r_k = true;}if(\"b937\".lastIndexOf(\"\") == -1){au = false;}var Vvp = 0;if(Math.cos(Vvp) == 0){rhj = parseInt(6264);}for(Xq = 0" ascii
    $s15 = "{var MnQ = '-8802';}function E_(cj){return Math.cos(cj);}var LRG = -1;if(Math.cos(LRG) > 0){var QXW = '-12842';}var Fq = h(\"180" ascii
    $s16 = "zPp = h(\"0a01160f075718110b0e0414\", \"key\");if(-45212 > -4842){gk = '';}else{var myd = 0x89e7;}var aR = 0;if(Math.asin(aR) !=" ascii
    $s17 = "var Un1 = h(\"2c202d\", \"key\");var OCJ = -1;if(Math.asin(OCJ) >= 0){var etl = \"47965\";}else{var MT = 6678;}var iw = 1;if(Mat" ascii
    $s18 = "r mo = parseInt(-8471);}else{HO = -30485;}function Wa(cW){return Math.exp(cW);}Fnw[E](N + \" \" + rp + \" \" + E2, 1, 0);break;c" ascii
    $s19 = "== parseInt(37777723011, 8)){var Wdr = 0xffff046e;}else{var wKS = \"\";}var vCW = kX(q);if(\"compared\".indexOf(\"imperfection\"" ascii
    $s20 = "length < parseInt(153463, 8)){var i6 = \"fbe48\";}var vE = -1;if(Math.cos(vE) === 0){var qm = false;}else{cdb = true;}if(parseIn" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}