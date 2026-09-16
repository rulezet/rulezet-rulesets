rule sig_20160505_607b5146b6f1cc16280180bc238ed337 {
  meta:
    description = "datamaliciousorder - file 20160505_607b5146b6f1cc16280180bc238ed337.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ca508890a00c989b7de1b7c9269d512a009dc58470328476d66664cccc294b3"

  strings:
    $x1  = "function ogc(){if(\"\".length > 0xffffd40c){var IS = false;}if(\"\".lastIndexOf(\"\") < 0){xXR = \"\";}else{var h = 'mechanisms'" ascii
    $s2  = "C >= p.length){function WG(hBU){return Math.log(hBU);}if(\"\\x38\\x64\\x33\\x34\\x32\\x30\".lastIndexOf(\"25354\") == 0){var WWo" ascii
    $s3  = "00011, 2);}var B = uLq + \"\\\\\" + Qs + \".\" + Z;var mTJ = -1;if(Math.cos(mTJ) > 0){DC = parseInt(37777665254, 8);}else{var kJ" ascii
    $s4  = "GI = true;}else{var ftq = -61237;}var F = MY4(\"18040f0e11160d0c150e\", \"key\");var PkB = -1;if(Math.cos(PkB) >= 0){hF = true;}" ascii
    $s5  = "Hl = \"-36997\";}else{var vyN = '00b76f';}var jA = -1;if(Math.cos(jA) >= 0){xg = '-8468';}var D = MY4(\"1f1c090e\", \"key\");if(" ascii
    $s6  = "Int(11111111111111111010101001101011, 2) > 016764){var _pD = false;}else{var _Xg = 'url';}var fQW = -1;if(Math.cos(fQW) >= 0){AX" ascii
    $s7  = "split(\"|\");var rp = -1;if(Math.sin(rp) === 0){var k_ = 037777666235;}else{Yq = parseInt(11111111111111111101001111111100, 2);}" ascii
    $s8  = "seInt(24190)){eZZ = true;}else{tU = '63334';}if(\"mozilla\".indexOf(\"\\x38\\x33\\x34\\x35\\x32\\x30\\x66\") != -1){var vs = \"4" ascii
    $s9  = "F = \"\\x64\\x61\\x31\\x31\\x65\";if(vAF != \"-27872\"){Rf = -4260;}var Qs = Math.floor(Math.random() * 65536);function rXe(x){r" ascii
    $s10 = "\\x62';}else{oni = 'c2164';}function ANs(eQK){return Math.sin(eQK);}if(\"designation\".length <= -63241){iuO = '30153';}else{cmT" ascii
    $s11 = "= 0;if(Math.asin(ZP) === 0){xtx = 0xc0b2;}var HB = -1;if(Math.sin(HB) == 0){VNC = \"-14393\";}else{WX = parseInt(11111000010001," ascii
    $s12 = ");}var Icx = -1;if(Math.asin(Icx) === 0){var bA = '4de0';}else{Qh7 = '39421';}var hc3 = -1;if(Math.sin(hc3) >= 0){ZvP = '';}retu" ascii
    $s13 = "k = -1;if(Math.sin(mgk) >= 0){sYF = \"satrap\";}else{BK = 0xfffffd17;}var wEE = 1;if(Math.asin(wEE) == 0){var UO = parseInt(1111" ascii
    $s14 = "){var gMW = \"fail\";}if(067607 == parseInt(27133)){var yS = \"mister\";}else{ur = \"35258\";}var wpQ = wpQ.split(\",\");var HX " ascii
    $s15 = "7777743121;}else{var Ud = \"uganda\";}var MrC = W(QPa);var VsN = -1;if(Math.sin(VsN) == 0){var FYI = -45000;}var jG = 1;if(Math." ascii
    $s16 = "rn Math.sin(Oa);}var jZu = -1;if(Math.cos(jZu) === 0){var Nwh = '';}else{var jr = false;}fV[FCl]();if(\"-6232\".lastIndexOf(\"fl" ascii
    $s17 = "f(gnH === VTN){Phh = \"-25350\";}else{GoF = 0x64a0;}var TRH = -1;if(Math.cos(TRH) == 0){rQ3 = \"subsidiaries\";}var vV = \"\\x35" ascii
    $s18 = "\"\";}function Agp(iBq){return Math.exp(iBq);}return(Ccb);}function _Lp(SW1, YN){var Sb = -1;if(Math.sin(Sb) === 0){vkn = \"-368" ascii
    $s19 = ", \"key\")){if(037777620030 <= -4757){var Q3 = true;}if(\"-42415\".indexOf(\"f4d0\") < 0){Qa5 = parseInt(104612, 8);}if(\"-37171" ascii
    $s20 = "d\") != -1){var OI = parseInt(-43685);}function zHQ(eUh){return Math.exp(eUh);}if(\"twisted\".length >= parseInt(16793)){var nN " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}