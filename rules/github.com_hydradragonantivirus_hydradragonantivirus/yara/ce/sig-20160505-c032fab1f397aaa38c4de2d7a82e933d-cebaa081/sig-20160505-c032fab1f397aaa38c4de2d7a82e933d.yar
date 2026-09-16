rule sig_20160505_c032fab1f397aaa38c4de2d7a82e933d {
  meta:
    description = "datamaliciousorder - file 20160505_c032fab1f397aaa38c4de2d7a82e933d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf74db2afa93db6754bc1918aaf41ef25d1500764453ac74f4999dde5c50941a"

  strings:
    $s1  = "function cu(Yy){if(\"origins\".indexOf(\"9308\") == 0){wJU = -49750;}else{Fbn = \"267d75d8\";}if(\"\" != \"\\x61\\x30\\x32\\x66" ascii
    $s2  = "rn Math.log(SYJ);}if(\"40702\".indexOf(\"magyar\") == -1){fYD = true;}else{var hxA = \"-42770\";}var Rw = -1;if(Math.asin(Rw) ==" ascii
    $s3  = "11101000111, 2);}else{H = 'day';}var fc1 = \"\";function o(yej){return Math.log(yej);}if(parseInt(111111111111111111110101000111" ascii
    $s4  = " kZ = \"-56298\";if(UWz != kZ){r7 = \"-39531\";}else{var rN = 'courier';}function Pgz(Skz){return Math.log(Skz);}if(\"2162aa36\"" ascii
    $s5  = ">= 0){var vv = \"30390\";}function lKa(sxX){return Math.log(sxX);}if(\"26915\".indexOf(\"18973\") == 0){VRP = parseInt(377776740" ascii
    $s6  = " vI(Nrw){return Math.log(Nrw);}var oM = 1;if(Math.cos(oM) != 0){var CN = parseInt(37777700776, 8);}var w = new Array();var qW = " ascii
    $s7  = " s5 = -1;if(Math.asin(s5) === 0){var UIP = false;}var bU = Hg(\"0f0915\", \"key\");}else{if(91 != 0x1cb8){wZ9 = false;}function " ascii
    $s8  = ".asin(cK);}if(037777625733 <= -63682){cn = true;}if(Ppd == Hg(\"263f\", \"key\")){if(\"\\x32\\x62\\x61\\x62\" != \"\\x37\\x36\\x" ascii
    $s9  = "91017\", \"key\");if(\"20211\".indexOf(\"-64284\") < 0){var Urv = \"-45426\";}else{var v3 = -28383;}if(\"cdd9c13\".indexOf(\"\\x" ascii
    $s10 = "i9 = -1;if(Math.cos(xi9) === 0){uT = '-54624';}else{jXL = '\\x33\\x35\\x33\\x33';}var Ki = 0;if(Math.asin(Ki) == 0){var eW_ = '" ascii
    $s11 = "th.sin(VA) == 0){ke = true;}else{cS = 037777734557;}var iy = cu(O);var lUQ = 1;if(Math.acos(lUQ) != 0){R_ = '';}else{var UL = -2" ascii
    $s12 = "B1 = false;}else{_NS = true;}var wO = -1;if(Math.asin(wO) > 0){Lp8 = '';}var vz = Hg(\"06160106094b451d14070d0d1f15\", \"key\");" ascii
    $s13 = " 8);}function _U(RHE){return Math.abs(RHE);}if(\"\\x31\\x37\\x32\\x35\\x30\\x35\\x35\\x37\" == \"\"){var EA = -11203;}var Q = \"" ascii
    $s14 = "0;if(Math.acos(qW) != 0){jm = '';}if(0xffffd735 != parseInt(41043, 8)){lN = false;}var hSa = -1;if(Math.cos(hSa) != 0){Nyz = fal" ascii
    $s15 = "Ks = -1;if(Math.acos(Ks) > 0){EM9 = 59593;}else{var qyc = true;}var jF4 = 0;if(Math.cos(jF4) == 0){X8 = '-49139';}var fH = -1;if" ascii
    $s16 = "4){var ra = -59948;}function Dz(Kt){return Math.round(Kt);}var _J = 0;if(Math.sin(_J) > 0){var tmJ = \"\\x33\\x36\\x61\\x63\\x32" ascii
    $s17 = "= -1;if(Math.sin(Jx) >= 0){var zB = true;}var zKm = 1;if(Math.sin(zKm) != 0){var NZv = 037777640306;}var _z = 0;if(Math.cos(_z) " ascii
    $s18 = "x34\\x34\\x39\\x30\\x34\\x64\") == -1){uf = false;}var zT = 0;if(Math.sin(zT) == 0){var dWj = \"malay\";}else{var Qy = 0xffff339" ascii
    $s19 = "th.cos(wpU) >= 0){var O9 = 'gear';}function CH_(pSV){return Math.cos(pSV);}if(\"c9c8246\".indexOf(\"23975\") != -1){var Lfn = 's" ascii
    $s20 = "1\\x35\\x32\\x35\\x36\\x61\\x36\";if(zm != \"50604\"){var sod = false;}else{var ol = 'c9d9edb';}var LRt = -1;if(Math.sin(LRt) >=" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}