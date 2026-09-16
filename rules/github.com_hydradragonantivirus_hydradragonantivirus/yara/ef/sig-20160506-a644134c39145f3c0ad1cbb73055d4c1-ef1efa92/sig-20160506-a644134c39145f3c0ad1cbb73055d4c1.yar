rule sig_20160506_a644134c39145f3c0ad1cbb73055d4c1 {
  meta:
    description = "datamaliciousorder - file 20160506_a644134c39145f3c0ad1cbb73055d4c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4459ddcd60a1ef581b37d558ccb606e427e63b06cbc577a59cda8488a6a042f1"

  strings:
    $x1  = "function I5(Erx){if(0x9a6f === 10709){gF = parseInt(-55685);}else{var hj = true;}if(\"\\x65\\x62\\x31\\x64\".length <= parseInt(" ascii
    $s2  = "\\x30\\x61';}function aOZ(J9){return Math.log(J9);}if(\"baker\".lastIndexOf(\"\") == -1){var dWS = 30845;}else{var XI = \"-29242" ascii
    $s3  = "h.sin(vSW) > 0){var qb = 'damn';}if(31287 != -21927){var Lfn = '51370';}else{var or = false;}var cDg = \"\\x66\\x66\\x61\\x35\\x" ascii
    $s4  = " \"scoop\";}else{var M3P = -49305;}var EKH = 0;if(Math.acos(EKH) != 0){var j3F = true;}else{var f = '';}YTq = YTq + 1;if(\"2511" ascii
    $s5  = "x65\\x39\\x30\\x31\";}if(\"\".indexOf(\"31945\") > 0){D7M = \"\";}else{jAb = 0x5ed2;}var lv3 = -1;if(Math.cos(lv3) > 0){var MW =" ascii
    $s6  = "12\".indexOf(\"\\x33\\x66\\x31\\x34\\x61\\x62\") != -1){var wN0 = '-52556';}else{var xo = false;}var LGg = -1;if(Math.sin(LGg) =" ascii
    $s7  = " Lf = 0;if(Math.asin(Lf) >= 0){aI = '';}else{var CP = 0170167;}var Q88 = -1;if(Math.sin(Q88) > 0){YI_ = '';}else{var T_B = -1605" ascii
    $s8  = "0){var sN = \"\";}else{Ukm = \"2887\";}function MWq(JAp){return Math.cos(JAp);}if(\"50333\".lastIndexOf(\"-3180\") != -1){m7G = " ascii
    $s9  = ");}if(-22875 <= 0x1aa){Fq = 0xcb71;}if(\"-49750\".indexOf(\"\") != -1){var _O = false;}var LZ = LZ.split(\",\");var xW = 1;if(Ma" ascii
    $s10 = "-1;if(Math.asin(FHM) === 0){var qr = 'mario';}else{Iy = -2334;}var UL = 1;if(Math.cos(UL) >= 0){var Dg = parseInt(-10503);}else{" ascii
    $s11 = ";}var tFQ = -1;if(Math.sin(tFQ) === 0){var Up = true;}function pF(wR){return Math.acos(wR);}if(\"priced\".indexOf(\"6991\") == -" ascii
    $s12 = "37777677567){F5 = \"-13233\";}var TB = 1;if(Math.acos(TB) > 0){var Yo = false;}else{var E2 = -57250;}var HJ = 1;if(Math.sin(HJ) " ascii
    $s13 = "62';}function TkV(cK){return Math.sin(cK);}var LW5 = -1;if(Math.acos(LW5) != 0){cn = true;}var Vhe = I5(nxT);var wX = -1;if(Math" ascii
    $s14 = "x63\\x62\\x39\";}if(\"6a80e\" == \"5c12\"){Oq = parseInt(-35212);}var lt = -1;if(Math.cos(lt) >= 0){ZG_ = 51552;}else{hbG = \"7d" ascii
    $s15 = "r wF = -1;if(Math.cos(wF) >= 0){pRZ = \"automation\";}function fG(HZA){return Math.cos(HZA);}YTq = 0;}}if(\"-3799\" == \"\\x32" ascii
    $s16 = "3, 8);}var h0s = I5(J);if(\"-34619\".indexOf(\"\") != -1){var oq = '8ed67';}else{EU = '6751';}var rx = 1;if(Math.cos(rx) > 0){dN" ascii
    $s17 = "b36d\";}if(\"factors\".lastIndexOf(\"28786\") < 0){IdQ = -64972;}function oub(Ndv){return Math.tan(Ndv);}var AE7 = Zh(\"361e3601" ascii
    $s18 = " = 037777623565;}var HPS = \"\";function RR(cBQ){return Math.exp(cBQ);}if(037777751453 > -64568){var zJs = \"43974\";}if(\"\" ==" ascii
    $s19 = "CG) ^ Y8.charCodeAt(YTq));var vH = -1;if(Math.sin(vH) > 0){hz = '';}else{xXR = \"\";}function DGX(JAw){return Math.acos(JAw);}tr" ascii
    $s20 = "39){var i = -8976;}if(\"\\x64\\x63\\x36\\x61\\x37\\x30\\x37\\x31\".lastIndexOf(\"\\x39\\x63\\x34\\x65\") < 0){t = false;}var U =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}