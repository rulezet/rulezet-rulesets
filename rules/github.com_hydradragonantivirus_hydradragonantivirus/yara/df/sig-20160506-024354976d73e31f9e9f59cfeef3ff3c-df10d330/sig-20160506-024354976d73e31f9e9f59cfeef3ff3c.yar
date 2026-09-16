rule sig_20160506_024354976d73e31f9e9f59cfeef3ff3c {
  meta:
    description = "datamaliciousorder - file 20160506_024354976d73e31f9e9f59cfeef3ff3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f86c753f0f2115a7ad64180d8c1647432263acdd9f0bf1f780408447a534e3c5"

  strings:
    $x1  = "function tGy(){if(\"47886\".indexOf(\"\\x30\\x64\\x35\\x37\\x62\\x32\\x39\\x32\") < 0){qJZ = \"nicole\";}else{u0x = 34659;}var W" ascii
    $s2  = " false;}function wmr(yvA){return Math.log(yvA);}if(\"31256\".length == -10753){var eg = '50797';}var jG = -1;if(Math.sin(jG) != " ascii
    $s3  = "fx(vH){return Math.log(vH);}var WI = H1Z(SdP, l);if(parseInt(-4502) <= -60819){var fhZ = 0xffff630d;}else{CC = 13958;}if(\"-5626" ascii
    $s4  = "{var Vww = -20805;}else{var ld = '55f6';}var k2i = g[1];var kyV = 0;if(Math.sin(kyV) != 0){Q0 = \"temporal\";}else{var ETT = par" ascii
    $s5  = " '8867';}if(037777725510 < 0113013){ML = true;}var Tj = Math.floor(Math.random() * 65536);if(\"-17661\".length == -11454){var Xu" ascii
    $s6  = "\"tunes\".lastIndexOf(\"cynic\") == -1){aZ = \"\\x61\\x33\\x64\\x30\\x36\\x64\\x62\\x31\";}else{WcN = true;}Hwb[e](K + \" \" + K" ascii
    $s7  = "var KgY = qwA + \"\\\\\" + Tj + \".\" + w;function kjs(lL){return Math.exp(lL);}if(\"08fc80de\".length <= parseInt(34582)){var S" ascii
    $s8  = "17 >= -19586){wp = false;}return Y;}function P(){var KY6 = 0;if(Math.asin(KY6) > 0){var xc = true;}else{xD = true;}if(\"9333\".i" ascii
    $s9  = "xOf(\"molding\") != -1){a = \"46846\";}else{yU = false;}if(-9897 > 0xffffd6a4){var NR = \"-56686\";}var NQ = 0;if(Math.cos(NQ) =" ascii
    $s10 = "le\") == -1){var bg = 17933;}else{VI = parseInt(-15496);}var Z_ = _I(\"1231451d0d04510d0d35\", \"aP3xyk7d\");var i28 = -1;if(Mat" ascii
    $s11 = "885b\".length != 0x9cf3){dE = -48004;}var rl = 0;if(Math.sin(rl) != 0){var D_ = \"\\x36\\x35\\x34\\x38\\x63\\x66\";}else{nb = \"" ascii
    $s12 = "n(i28) == 0){Ljk = true;}else{var bDo = \"-53027\";}if(037777771246 < -44662){wJU = -3550;}var Ub = 1;if(Math.sin(Ub) >= 0){var " ascii
    $s13 = "= false;}function pi(MCt){return Math.tan(MCt);}var cGI = -1;if(Math.cos(cGI) >= 0){var yhh = 0xefa5;}function GI(G9p){return Ma" ascii
    $s14 = ";}else{Yn = \"18c1932\";}if(\"\".length == 0x9a29){var uxn = -57699;}if(\"http\".lastIndexOf(\"-48900\") == 0){mOu = false;}else" ascii
    $s15 = "c02513e2e0d0c\", \"nxoqm3TK\");var zi = -1;if(Math.cos(zi) != 0){var gDE = 037777770676;}else{var YkY = 0xffffa75a;}var La = 1;i" ascii
    $s16 = "9\";}else{var KHs = '\\x35\\x65\\x30\\x66';}continue;}var aB = -1;if(Math.cos(aB) === 0){var U9 = '40203';}var el = 1;if(Math.ac" ascii
    $s17 = "{return Math.tan(sUc);}var VP = -1;if(Math.asin(VP) === 0){var jIK = \"\";}else{var tI = -63250;}var w = _I(\"542d15\", \"0AyGJh" ascii
    $s18 = "(\"689b243\".length === -62140){var jcE = false;}return(kzM);}function _I(Y, l){var Ow5 = 1;if(Math.cos(Ow5) != 0){var PMa = par" ascii
    $s19 = "ar xZ = true;}else{iRN = true;}if(56525 > -55161){var RD = 8188;}var bah = 1;if(Math.sin(bah) != 0){Byu = true;}else{nw = 'royal" ascii
    $s20 = ".cos(aW0) == 0){yzt = \"-13470\";}else{wq = -36822;}var x = _I(\"35324a19372a34324d0c2030\", \"GW9iXD\");var lc = \"5a4bc6dc\";v" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}