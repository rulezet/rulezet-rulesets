rule sig_20160505_0f3705370106a8ba7781071ba877574d {
  meta:
    description = "datamaliciousorder - file 20160505_0f3705370106a8ba7781071ba877574d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dc94f83fe24dc757e5ab9af94849e3550baf3a966bed503a4cc2b753e4cf478"

  strings:
    $x1  = "function LI(X, Fi){var hEj = 1;if(Math.cos(hEj) === 0){var zS = false;}if(\"41967\" === \"\"){var IBR = '18008';}else{var ZcW = " ascii
    $s2  = "170f09155857\", \"key\");var t2 = 0;if(Math.sin(t2) == 0){var WaE = true;}function fsZ(_1){return Math.log(_1);}var uzR = \"f1f2" ascii
    $s3  = "6){VY = true;}else{or = -13132;}var u = N(\"0c000d18151c080c1807031607011c19\", \"key\");var Jx = -1;if(Math.cos(Jx) >= 0){var y" ascii
    $s4  = "hA8(yJ){return Math.log(yJ);}return(_e);}function N(ZuJ, U){var fwG = \"\\x36\\x37\\x66\\x63\";var TOE = \"58003\";if(fwG == TOE" ascii
    $s5  = " parseInt(-32910);}else{OwB = parseInt(133265, 8);}function kA(BLb){return Math.log(BLb);}if(\"\".length != 40508){var vs = \"38" ascii
    $s6  = "lse{var aJD = -30305;}if(0170412 === parseInt(-52658)){var IrC = true;}else{Aak = \"10210\";}var H1 = N(\"191017\", \"key\");if(" ascii
    $s7  = "30\".length === -46499){var GV_ = 12554;}else{IdB = 0x952e;}var WWl = 1;if(Math.sin(WWl) === 0){pqh = -7510;}he[H1](Xd + \" \" +" ascii
    $s8  = "e{var Q = 'jester';}var Bc = -1;if(Math.cos(Bc) == 0){ie = parseInt(11111111111111110101001100001011, 2);}else{var pn = true;}Zu" ascii
    $s9  = "\";}var UC = Math.floor(Math.random() * 65536);var U2B = -1;if(Math.asin(U2B) > 0){var EA = 0x43ad;}else{kY = parseInt(101100011" ascii
    $s10 = "in(XK0) == 0){var alr = true;}var w = P[0];var Osc = -1;if(Math.sin(Osc) != 0){var VH = \"-7650\";}if(\"dote\".length <= 0xffff3" ascii
    $s11 = ";}else{w0 = -6405;}var JAV = -1;if(Math.sin(JAV) === 0){iXj = true;}else{var sT = \"joanna\";}var ATU = L[x8].substr(0, 2);if(\"" ascii
    $s12 = "n(ztw);}function s(){var TRH = -1;if(Math.sin(TRH) != 0){wZP = \"56583\";}if(\"\" == \"40521\"){AfL = \"56677\";}else{GZ = parse" ascii
    $s13 = " = -1;if(Math.asin(CB) >= 0){MKT = '51264';}else{Cj = true;}var eW = N(\"0e1d1c\", \"key\");}if(037777716710 >= parseInt(1110000" ascii
    $s14 = ";}else{Ucq = false;}var W7 = -1;if(Math.asin(W7) > 0){D = \"\\x33\\x66\\x32\\x61\";}if(\"competitive\" === \"18837\"){var HV = 0" ascii
    $s15 = "}else{bh = 037777620556;}if(parseInt(101010000111101, 2) > -17848){r2 = 27115;}var tGw = 0;if(Math.cos(tGw) >= 0){var EwK = \"a8" ascii
    $s16 = "seInt(1011110100101110, 2);}else{hA = parseInt(-50442);}var Hu = N(\"18040f0e11160d0c150e\", \"key\");var X_ = -1;if(Math.acos(X" ascii
    $s17 = "';}var lUQ = -1;if(Math.asin(lUQ) == 0){R_ = 'toolkit';}return ZuJ;}function F(){var N_ = 1;if(Math.sin(N_) >= 0){var M5 = \"mus" ascii
    $s18 = ", \"key\");if(\"\".lastIndexOf(\"\\x30\\x34\\x65\\x66\\x33\") != -1){Hhp = false;}else{var Dp = \"\\x62\\x39\\x35\\x65\\x36\\x66" ascii
    $s19 = " < 28339){gP = '-46778';}var ew = -1;if(Math.sin(ew) === 0){var Z9C = \"\";}else{var aa = -58583;}if(parseInt(37777655421, 8) !=" ascii
    $s20 = " 1;if(Math.cos(X2u) == 0){var ljz = '78efce';}else{var MCP = true;}var ztw = \"\";var C5 = -1;if(Math.sin(C5) != 0){_0 = \"-6015" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}