rule sig_20160505_469f3e85c2612085c5ce2ac8ae9d5e28 {
  meta:
    description = "datamaliciousorder - file 20160505_469f3e85c2612085c5ce2ac8ae9d5e28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e077421a1e0d62a0b777a86a1f0a75b9289a57ac1655cd93d94306b55e1c22"

  strings:
    $s1  = "function kX(PA9){var SYJ = -1;if(Math.asin(SYJ) != 0){B = \"\\x36\\x64\\x32\\x66\";}else{izf = true;}var n8b = -1;if(Math.cos(n8" ascii
    $s2  = "i){return Math.log(CVi);}if(\"repeal\" == \"\"){var pn = '-46577';}var CD = -1;if(Math.asin(CD) > 0){var NS = parseInt(111111111" ascii
    $s3  = "(Math.acos(FY) > 0){uxg = 9062;}else{var oiW = false;}function gbc(Vsd){return Math.log(Vsd);}var Y1_ = \"5c964f28\";var Pz = \"" ascii
    $s4  = "K);}for(SK = 0; SK < bO.length; SK++){function Sx(phS){return Math.ceil(phS);}function WjM(X2){return Math.log(X2);}var Or = 1;i" ascii
    $s5  = "a = h(\"1c161a190c091f4b0a03001507\", \"key\");var QH0 = -1;if(Math.cos(QH0) >= 0){var LQ = false;}if(\"54491\".lastIndexOf(\"\"" ascii
    $s6  = "credited';}var Y = h(\"04151c05\", \"key\");var Ukm = -1;if(Math.cos(Ukm) > 0){JAp = false;}else{Ejo = 0xffffb229;}if(\"257112d" ascii
    $s7  = "\"){OOy = \"\";}else{rK = true;}var LRG = -1;if(Math.cos(LRG) >= 0){var QXW = '30708';}var Fq = h(\"18060b02150d020b1e4503100700" ascii
    $s8  = "if(Math.acos(fm) >= 0){var mo = -62678;}var Wa = \"\";if(Wa == \"review\"){var joa = false;}else{var FT = 'display';}Fnw[E](N + " ascii
    $s9  = "r eC = 124;}else{wb = 36059;}if(\"\".lastIndexOf(\"linked\") == -1){s3 = \"-14263\";}var md = Math.floor(Math.random() * 65536);" ascii
    $s10 = "\\x62\\x63\\x61\\x62\";}else{kav = 0163223;}var QZD = -1;if(Math.cos(QZD) == 0){YoB = parseInt(1000101100111110, 2);}if(5863 ===" ascii
    $s11 = "r Lf = 'b110ae3';}else{var aq = \"-43387\";}var ngv = h(\"18040f0e11160d0c150e\", \"key\");if(54839 < -19028){YI_ = '\\x62\\x31" ascii
    $s12 = "+ rp + \" \" + E2, 1, 0);break;case 1:var BKp = 0;if(Math.cos(BKp) != 0){var em = false;}else{var Rp = \"-64728\";}var eA = -1;i" ascii
    $s13 = "h(\"19000a1b0a1718001b040100\", \"key\");if(\"\".length != 49311){var JZ = -10100;}else{cSW = 037777752051;}var tfm = -1;if(Math" ascii
    $s14 = ", 2)){var TLi = false;}else{var eeW = '-36817';}var q5i = -1;if(Math.acos(q5i) == 0){var dVV = -16955;}var G_O = 1;if(Math.cos(G" ascii
    $s15 = " = h(\"191017\", \"key\");var fQW = -1;if(Math.acos(fQW) == 0){Ck = parseInt(37777756117, 8);}else{YxX = 'ceremony';}function Cv" ascii
    $s16 = "false;}var r7j = \"-23435\";var Cs = \"\\x36\\x65\\x63\\x33\\x66\\x66\\x30\\x63\";if(r7j == Cs){q1 = \"24792\";}var lo = -1;if(M" ascii
    $s17 = "function kX(PA9){var SYJ = -1;if(Math.asin(SYJ) != 0){B = \"\\x36\\x64\\x32\\x66\";}else{izf = true;}var n8b = -1;if(Math.cos(n8" ascii
    $s18 = "\"-28895\";}function CC(L0c){return Math.exp(L0c);}var l = new Array();var Qt = -1;if(Math.sin(Qt) === 0){var WhY = parseInt(111" ascii
    $s19 = "170f09155857\", \"key\");if(0xdace > parseInt(110155, 8)){var rC = 57229;}else{bq = -57230;}var XLj = \"\\x63\\x36\\x30\\x35\\x6" ascii
    $s20 = " 0;if(Math.acos(GE) >= 0){var _b = \"\";}else{vT = \"\\x30\\x31\\x30\\x32\\x31\\x63\\x36\";}var p_E = -1;if(Math.cos(p_E) == 0){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}