rule sig_20160505_d88c2132a783fc3e6179795e58a99257 {
  meta:
    description = "datamaliciousorder - file 20160505_d88c2132a783fc3e6179795e58a99257.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f8fb1e7115bc0d5a639db1e2ff7b8107cfdfc480c54d3c2b236c0bf83828e7a"

  strings:
    $s1  = "function wW(BC, rQT){var wX = 0;if(Math.sin(wX) == 0){var L = '-10992';}if(\"complicate\" == \"\\x61\\x65\\x35\\x32\\x32\\x66\")" ascii
    $s2  = " = j(\"0a01160f075718110b0e0414\", \"key\");function wO(wZS){return Math.log(wZS);}var s7 = \"-64023\";if(s7 != \"\"){NK = \"dan" ascii
    $s3  = "e{var I4 = false;}var cQ = -1;if(Math.cos(cQ) == 0){NSo = true;}var vWI = j(\"1f1c090e\", \"key\");var ZC = 1;if(Math.cos(ZC) ==" ascii
    $s4  = "key\");var dhK = -1;if(Math.cos(dhK) === 0){var EiQ = 'convention';}if(\"21239\".lastIndexOf(\"14689\") == 0){dLd = false;}else{" ascii
    $s5  = "tribes\") > 0){FQ = true;}var Iim = j(\"0f0915\", \"key\");}else{var x_o = -1;if(Math.sin(x_o) >= 0){gD = \"4818\";}var EWi = 1;" ascii
    $s6  = "return Math.sqrt(o);}if(parseInt(37777750751, 8) === -50492){nSz = \"-37261\";}else{GF = 0132166;}oDH = oDH + 1;if(parseInt(4535" ascii
    $s7  = "38\\x31\";}var xG = -1;if(Math.cos(xG) === 0){WYJ = \"a3577dab\";}function ML(rZv){return Math.ceil(rZv);}var e = w[3];var GO = " ascii
    $s8  = "= true;}var Vi = new Array();var jr = 0;if(Math.asin(jr) == 0){var HGL = '';}else{var kBT = true;}var YbU = -1;if(Math.cos(YbU) " ascii
    $s9  = " = true;}else{TEA = true;}var NOh = 1;if(Math.cos(NOh) != 0){PZ = false;}else{YrS = false;}var XIL = Math.floor(Math.random() * " ascii
    $s10 = "b(g);var Xv = -1;if(Math.sin(Xv) > 0){h2n = false;}else{jbf = '-35410';}if(\"\".lastIndexOf(\"1f50\") == 0){GL = \"\";}if(\"rank" ascii
    $s11 = "e;}function Vgg(YFF){return Math.ceil(YFF);}var cs = -1;if(Math.cos(cs) == 0){var WjY = \"-28909\";}if(\"20293\".length === pars" ascii
    $s12 = "01000000, 2)){n_Q = \"d3e185\";}else{pjM = parseInt(18172);}var TNz = -1;if(Math.sin(TNz) === 0){var wN = true;}else{var FKn = 4" ascii
    $s13 = "0';}function zo(K7I){return Math.sin(K7I);}if(oDH >= rQT.length){var pEb = -1;if(Math.sin(pEb) > 0){lr = \"b2e7d5c7\";}else{var " ascii
    $s14 = "boP < S.length; boP += 2){var jRL = -1;if(Math.cos(jRL) != 0){sE = true;}if(-31261 < 32096){var fkk = true;}if(parseInt(37777631" ascii
    $s15 = "C = '\\x61\\x65\\x32\\x39\\x66\\x33';}var Tv = 0;if(Math.sin(Tv) != 0){var mr = '3965';}else{var CLJ = \"suck\";}var qz = -1;if(" ascii
    $s16 = " yVc = -1;if(Math.cos(yVc) >= 0){var sk = true;}else{RPG = '\\x63\\x66\\x38\\x33\\x37\\x37';}var U0j = j(\"19000a1b0a1718001b040" ascii
    $s17 = "37777607030;}var Hm = 0;if(Math.sin(Hm) == 0){wn4 = '-11811';}else{var iWl = 0xffffddf3;}var yXU = J_x + \"\\\\\" + XIL + \".\" " ascii
    $s18 = "else{var CU = '7a101';}var pzt = -1;if(Math.sin(pzt) != 0){var nFf = false;}if(\"type\".indexOf(\"51964\") != -1){var aQ = true;" ascii
    $s19 = "g\";var kGI = \"styx\";if(piN == kGI){var WP = true;}else{fI = true;}var VOA = -1;if(Math.sin(VOA) != 0){var zjD = parseInt(3777" ascii
    $s20 = "1, 2)){Sae = false;}if(\"7b3f65a\".indexOf(\"10305\") != -1){XW5 = false;}else{o_j = 'loath';}var xpl = 0;if(Math.cos(xpl) === 0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}