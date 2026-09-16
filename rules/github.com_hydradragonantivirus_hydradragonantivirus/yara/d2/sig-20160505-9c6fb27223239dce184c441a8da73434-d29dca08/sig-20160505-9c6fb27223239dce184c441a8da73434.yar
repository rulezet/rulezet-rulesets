rule sig_20160505_9c6fb27223239dce184c441a8da73434 {
  meta:
    description = "datamaliciousorder - file 20160505_9c6fb27223239dce184c441a8da73434.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7a40834daf812f524a6df18bddc476d5b0414fd0199055b6079fecbe6b6c1e"

  strings:
    $x1  = "function tv7(Czq, vz){var v = 1;if(Math.sin(v) === 0){var XWD = parseInt(11111111111111111010111011000010, 2);}if(\"53711\".inde" ascii
    $s2  = "4\\x35\\x34';}function YB(_C_){return Math.log(_C_);}function N2(tND, m2){return Math.atan2(tND, m2);}function zO(JY){return Mat" ascii
    $s3  = "n Math.log(fr);}function INe(FQ){return Math.abs(FQ);}if(\"\".indexOf(\"sine\") < 0){jnr = true;}if(\"\\x65\\x33\\x66\\x31\\x33" ascii
    $s4  = "ath.cos(Tn) != 0){var _Ja = 27433;}else{var xnQ = \"\\x31\\x61\\x39\\x66\\x35\\x33\\x30\\x65\";}var J1k = -1;if(Math.sin(J1k) >=" ascii
    $s5  = " vxO = -1;if(Math.sin(vxO) > 0){var AGt = parseInt(11111111111111111011010010001001, 2);}else{var ahI = \"60074\";}r[cBQ] = 1;}}" ascii
    $s6  = "in(OfQ) >= 0){Vsd = \"641d\";}if(\"58b2e4\".length > -60943){Yt1 = 'scanned';}else{RS = false;}var O = E + \"\\\\\" + HV + \".\"" ascii
    $s7  = "r Cn = \"praise\";}else{var YWA = false;}var fz = tv7(\"0c000d18151c080c1807031607011c19\", \"key\");var OQ9 = 1;if(Math.sin(OQ9" ascii
    $s8  = " * 65536);var uX8 = -1;if(Math.asin(uX8) > 0){var uX2 = '40310';}else{Dx = '-41307';}function N1(His){return Math.floor(His);}if" ascii
    $s9  = "r Bt1 = '';}B = B + 1;if(\"\".indexOf(\"154f59\") != -1){qmG = false;}if(\"4ac72cb\".length >= parseInt(111111111111111101011001" ascii
    $s10 = " oi = 0;if(Math.cos(oi) > 0){var q2I = 'sized';}return Czq;}function RR(){if(\"40417\".indexOf(\"94f6d\") != -1){mOu = true;}els" ascii
    $s11 = "f(\"leaders\".length == -39671){i4 = true;}if(\"chronicles\" === \"clown\"){var dWj = \"15413\";}var alT = 0;if(Math.sin(alT) ==" ascii
    $s12 = " iQP = 1;if(Math.cos(iQP) >= 0){var fYD = -59372;}else{var hxA = \"overdue\";}if(B >= vz.length){var CEk = 0;if(Math.sin(CEk) >=" ascii
    $s13 = "== \"3468\"){V_j = '-26058';}var y_H = -1;if(Math.sin(y_H) >= 0){var DN = false;}function g9N(sY5){return Math.tan(sY5);}if(\"pi" ascii
    $s14 = "f(Math.cos(UN) >= 0){rm = \"-50021\";}else{var qV = '04c8c4a';}var E = ji[fz](2);var jo = -1;if(Math.acos(jo) > 0){xRJ = '-21494" ascii
    $s15 = "jC = -1;if(Math.cos(wjC) === 0){var avm = parseInt(1100100000100001, 2);}else{kfA = parseInt(14952);}var l1 = 0;if(Math.asin(l1)" ascii
    $s16 = "'19270';}var jRi = -1;if(Math.cos(jRi) === 0){r0 = \"zechariah\";}else{ge = false;}var P = ehn[D].split(\"|\");var Ugz = -1;if(M" ascii
    $s17 = "4\\x38\\x63\\x61\";}else{var FMw = '-22398';}function _fZ(AX){return Math.tan(AX);}if(\"52522\" == \"\"){Uq = -14867;}else{var _" ascii
    $s18 = " = 'cremona';}if(\"7660\".lastIndexOf(\"\") != -1){var j3F = false;}var eZs = -1;if(Math.cos(eZs) >= 0){_3 = true;}else{var g1 =" ascii
    $s19 = "){var yfZ = '6b67';}var TqV = 1;if(Math.sin(TqV) === 0){avd = false;}else{JX = '\\x31\\x33\\x34\\x30\\x33\\x35\\x31\\x38';}var U" ascii
    $s20 = "se;}var pTa = -1;if(Math.cos(pTa) > 0){var K1Y = true;}else{var LFv = '40590';}function N4c(BW){return Math.atan(BW);}Czq += Str" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}