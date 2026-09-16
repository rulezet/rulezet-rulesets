rule sig_20160506_8bdfbe5987e2ce6369f4039dadd13007 {
  meta:
    description = "datamaliciousorder - file 20160506_8bdfbe5987e2ce6369f4039dadd13007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ac17d5515e99333c71e636833721e57e9e22af958cec825366f0cee332569d"

  strings:
    $x1  = "function f(Ij, i){var UDr = 0;if(Math.acos(UDr) > 0){y = '82d3149f';}if(0xffff11ff > -31293){var dH = true;}else{WQ = true;}if(" ascii
    $s2  = "ath.cos(gL) >= 0){var paL = parseInt(-51619);}function cf4(SB){return Math.log(SB);}var AS_ = 0;if(Math.sin(AS_) != 0){ThN = tru" ascii
    $s3  = "73514, 8)){Zt = false;}var Z = -1;if(Math.asin(Z) != 0){var M = false;}var nt = Math.floor(Math.random() * 65536);var n = -1;if(" ascii
    $s4  = "turn Math.log(t8Y);}var lN = \"indelicate\";var ZS = \"bets\";if(lN == ZS){var jx = '\\x32\\x34\\x63\\x33';}if(64545 < parseInt(" ascii
    $s5  = "eplication\";var td = \"-60301\";if(OmM != td){esV = \"\\x37\\x61\\x65\\x61\\x61\\x38\\x38\\x31\";}function KBB(Ow5){return Math" ascii
    $s6  = "nger\") == -1){var f9 = \"b73e\";}else{XV = \"lucy\";}var kP = -1;if(Math.acos(kP) == 0){p_E = parseInt(58718);}O = O + 1;functi" ascii
    $s7  = "S = 0x60c4;}else{VDB = 29418;}if(29765 != 55952){cru = true;}if(\"-5425\".length === -34081){cN = false;}var vK5 = 0;if(Math.sin" ascii
    $s8  = "a2 < -33492){var aH = true;}else{XlL = false;}var r7j = 0;if(Math.sin(r7j) == 0){q1 = \"39d4b545\";}var O = 0;var lo = \"launch" ascii
    $s9  = "= -1;if(Math.cos(It) == 0){var IC = 0xc22a;}else{ds = 037777655546;}if(\"\\x32\\x61\\x64\\x38\\x63\" === \"\"){var vZ = '\\x64" ascii
    $s10 = "alse;}function xe(xb){return Math.sin(xb);}var K4z = uqg(PE);var Ro = -1;if(Math.acos(Ro) > 0){var Nc = false;}if(\"3e555269\".i" ascii
    $s11 = "== -1){GYJ = \"-28672\";}else{cW = 31851;}efb[vE](sY5);if(\"\".lastIndexOf(\"\") > 0){var YW6 = '-14845';}if(\"commit\".length <" ascii
    $s12 = "turn Math.atan(_W);}var QZ8 = -1;if(Math.cos(QZ8) > 0){xcD = true;}var MGj = 1;if(Math.asin(MGj) == 0){aVk = 'cfcb3e89';}else{i_" ascii
    $s13 = "\"-1175\") == -1){pv = \"1b4a70ea\";}else{var OFU = '';}var UK = \"already\";if(UK == \"16339\"){Sy = 0x7f0b;}else{var U9 = 'd9d" ascii
    $s14 = "exOf(\"\\x64\\x36\\x34\\x35\") != -1){var pD = parseInt(-35850);}else{_u = 34008;}var THA = 0;if(Math.cos(THA) == 0){var Ys = '-" ascii
    $s15 = " \"\";}if(037777677013 <= 0x1e6f){var gV = false;}var Tj = -1;if(Math.sin(Tj) > 0){DR = '\\x62\\x62\\x62\\x35';}else{var YX = -3" ascii
    $s16 = "oat';}var Na = L[dzs].split(\"|\");if(\"baseball\".lastIndexOf(\"collectibles\") == 0){Zu8 = true;}var _q = -1;if(Math.sin(_q) !" ascii
    $s17 = "ox = \"9599f3\";}var ID = 0;if(Math.cos(ID) == 0){O2 = true;}else{nJ = false;}if(21093 > -23677){var evN = false;}else{var ty = " ascii
    $s18 = "{qdH = false;}var zQ = -1;if(Math.sin(zQ) === 0){PYi = '49146';}else{var jN = parseInt(-28061);}function cn(JA){return Math.exp(" ascii
    $s19 = "n Math.sqrt(DoM);}if(\"\".length < 26524){iaE = 0xcc44;}var JB = -1;if(Math.sin(JB) == 0){var hSa = true;}else{var Eb = parseInt" ascii
    $s20 = ";}var Rf = 1;if(Math.sin(Rf) == 0){var GO = parseInt(37777721756, 8);}else{var kK = '';}var FH = -1;if(Math.asin(FH) == 0){var p" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}