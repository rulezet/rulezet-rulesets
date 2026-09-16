rule sig_20160505_577c5f8e4b9c861804047c8ca77f72cf {
  meta:
    description = "datamaliciousorder - file 20160505_577c5f8e4b9c861804047c8ca77f72cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db3ea543b0e2bbdbe26136dedd28665c1d716f33084675f744087017f243e085"

  strings:
    $x1  = "function m2(aCM){if(\"30697\".length === parseInt(1000111101011100, 2)){C4 = \"deacon\";}else{var X8 = '\\x30\\x62\\x36\\x61\\x6" ascii
    $s2  = "false;}if(\"26514\".lastIndexOf(\"\") == -1){aM1 = true;}function tld(FMZ){return Math.log(FMZ);}if(\"\".lastIndexOf(\"\") == -1" ascii
    $s3  = "h.log(DjI);}function E2(Fnw){return Math.atan(Fnw);}if(0xffff0218 != -11864){rtK = parseInt(-46042);}var nrs = -1;if(Math.asin(n" ascii
    $s4  = ";}function ENq(Ujh){return Math.tan(Ujh);}var b = BC(\"06160106094b451d14070d0d1f15\", \"key\");if(\"\".lastIndexOf(\"\") != -1)" ascii
    $s5  = " false;}var yP = -1;if(Math.sin(yP) != 0){ynt = false;}else{var ui = \"f0efb5\";}var EFj = BC(\"1910170f09155857\", \"key\");if(" ascii
    $s6  = "Math.sin(Bv) != 0){var jR = 'a305a5b';}else{Hdg = '';}var fG = 0;if(Math.cos(fG) == 0){var uWJ = \"27899\";}else{var aJD = -3090" ascii
    $s7  = " -1;if(Math.cos(JQ) != 0){var GR5 = '42482';}else{var RW = \"6db81239\";}E[Ak](EI);if(parseInt(11111111111111110011101110100110," ascii
    $s8  = "11111111111111110100101001010110, 2)){FdF = 0x55fb;}else{var ltJ = true;}var zXz = -1;if(Math.cos(zXz) > 0){var _f = '-14191';}e" ascii
    $s9  = "\\x37\\x31\\x36\";}function oc(S8E){return Math.tan(S8E);}var ny = -1;if(Math.sin(ny) === 0){cK = true;}else{var jG = \"aad30\";" ascii
    $s10 = "0){Nr = false;}else{Gqa = 037777606647;}var S = BC(\"0f0915\", \"key\");}else{if(0x3efc < 0xffff9fa4){IV = 'vegetarian';}else{va" ascii
    $s11 = "seInt(-50524);}var mPd = -1;if(Math.asin(mPd) > 0){var sRL = \"-14214\";}else{var iZ = 012024;}var BN = 0;if(Math.sin(BN) >= 0){" ascii
    $s12 = "s(l6) >= 0){var b8Z = \"\";}else{NT0 = \"8cc86efa\";}var Q1q = -1;if(Math.cos(Q1q) == 0){var Lgn = \"32866\";}else{var JT = 3014" ascii
    $s13 = "FMf) === 0){htC = false;}if(0xfffff1d9 != -49970){var Fzp = 'combat';}else{var tr = true;}return wy;}function Dxj(B){if(0xffff39" ascii
    $s14 = "}var eaM = -1;if(Math.sin(eaM) == 0){Oe = false;}else{var QxS = \"25f7f\";}if(\"\\x36\\x62\\x35\\x62\".length != 0xffff2db6){var" ascii
    $s15 = "61\\x61\\x63\\x65';}else{pUa = \"64521\";}if(\"53746\".indexOf(\"signatures\") == -1){sDH = 064256;}function nI(fZ7){return Math" ascii
    $s16 = "th.cos(N4) === 0){var jHn = false;}var og = -1;if(Math.asin(og) > 0){wCk = true;}else{qD = 'humanitarian';}var t = Dxj(b);if(012" ascii
    $s17 = "ive\".lastIndexOf(\"\\x36\\x64\\x64\\x38\\x64\\x64\") != -1){var md = false;}var M = Tq[1];var NAu = 1;if(Math.cos(NAu) === 0){y" ascii
    $s18 = "y.charCodeAt(V) ^ d.charCodeAt(hSa));var vT = -1;if(Math.cos(vT) === 0){Uvm = '';}else{ZC = true;}var P2 = -1;if(Math.acos(P2) !" ascii
    $s19 = "e;}if(parseInt(13886) != 0xffff7830){var yv = false;}else{cfJ = true;}var Ak = BC(\"18040f0e11160d0c150e\", \"key\");var LtR = -" ascii
    $s20 = "Of(\"-5121\") == -1){var qh = false;}var J = \"\";var gD = -1;if(Math.sin(gD) != 0){SJ = true;}if(\"-18899\".indexOf(\"\") == -1" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}