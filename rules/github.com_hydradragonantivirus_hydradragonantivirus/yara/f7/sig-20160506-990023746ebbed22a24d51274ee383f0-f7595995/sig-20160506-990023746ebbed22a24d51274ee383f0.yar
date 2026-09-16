rule sig_20160506_990023746ebbed22a24d51274ee383f0 {
  meta:
    description = "datamaliciousorder - file 20160506_990023746ebbed22a24d51274ee383f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebf1895137b1af2bc1e68644d5055999147697ce63c27ca1ba7e445b7b8e144b"

  strings:
    $s1  = "function Kc(){var s = \"-47851\";if(s == \"\\x37\\x33\\x31\\x64\\x37\\x66\\x35\"){R = 'hub';}var rC = \"62440\";var q = \"disrup" ascii
    $s2  = "){return Math.log(fY);}var Gs = -1;if(Math.asin(Gs) != 0){SuH = 'e9c6e8e';}var Bm = 1;if(Math.acos(Bm) != 0){var hh = 0xe782;}va" ascii
    $s3  = "61\";}function eql(jN){return Math.log(jN);}var ZP = \"-28699\";if(ZP === \"63687\"){var l54 = true;}var OmM = -1;if(Math.acos(O" ascii
    $s4  = "085c2a1c45383f2e0655\", \"MKg8H26L\");function qvZ(hxA){return Math.log(hxA);}if(\"60121\".lastIndexOf(\"\\x38\\x31\\x65\\x61\\x" ascii
    $s5  = "h.cos(QZD) === 0){YoB = 037777657535;}else{FEN = \"\\x65\\x39\\x39\\x65\\x32\";}function BrF(QMQ){return Math.log(QMQ);}continue" ascii
    $s6  = "true;}var h5u = \"libel\";if(h5u != \"-45046\"){var OA = \"\";}else{var ulj = true;}function HBe(yyR){return Math.log(yyR);}var " ascii
    $s7  = "(\"\\x35\\x30\\x34\\x36\".length == 037777771417){m = \"06526b\";}else{en = true;}hp = hp + 1;var E2 = -1;if(Math.acos(E2) > 0){" ascii
    $s8  = "se{H_i = \"-62358\";}var cV = \"\\x36\\x39\\x63\\x37\";if(cV != \"-47748\"){gD = \"c04c\";}else{var xW8 = '37192';}var EWi = -1;" ascii
    $s9  = "!= 0){PK = parseInt(1809);}function T1h(sHX){return Math.sin(sHX);}var ON = -1;if(Math.asin(ON) >= 0){JPT = \"\";}if(\"\".indexO" ascii
    $s10 = "ar Eov = -1;if(Math.sin(Eov) === 0){var jUF = '';}else{var nsh = true;}var knj = hSa[ye].substr(0, 2);if(\"96775\".lastIndexOf(" ascii
    $s11 = "f(Math.sin(oO) != 0){var SM = \"14678db8\";}else{var R2n = false;}var tF = -1;if(Math.sin(tF) != 0){Tj = true;}else{var pW = \"" ascii
    $s12 = "B = -1;if(Math.sin(JB) != 0){var waE = false;}var ed = \"\\x38\\x33\\x34\\x65\\x34\\x33\\x35\\x38\";var oR = \"0258814\";if(ed =" ascii
    $s13 = "-1;if(Math.cos(QFf) == 0){mc = -4777;}var lml = 0;if(Math.sin(lml) > 0){tk = '';}if(parseInt(-10518) != 033266){var zPD = true;}" ascii
    $s14 = "5ldmOWD\");if(\"e20b21ae\".length > -10596){uf = true;}else{var xhA = \"\";}var UrE = -1;if(Math.sin(UrE) != 0){var Mj = \"-4355" ascii
    $s15 = "2d5 < -30896){var qD = '';}else{zo = '\\x64\\x37\\x35\\x37\\x37\\x31\\x39';}var dp = 1;if(Math.sin(dp) > 0){cT = '';}if(parseInt" ascii
    $s16 = "!= -1){var wwZ = parseInt(146133, 8);}var Cs = -1;if(Math.sin(Cs) === 0){OLB = false;}else{var Uv = \"\";}function DoM(WPm){retu" ascii
    $s17 = "= -1;if(Math.cos(ZS) >= 0){_YP = 037777764313;}if(\"\".indexOf(\"11d0f51\") == -1){xi = \"\\x32\\x66\\x39\\x33\\x62\\x36\\x39\";" ascii
    $s18 = "nxG = \"\";var BI = \"hundredweight\";if(nxG != BI){y2c = false;}var ny = -1;if(Math.sin(ny) != 0){cK = true;}else{var jG = \"03" ascii
    $s19 = "Rh = -59745;}var iFs = 1;if(Math.cos(iFs) === 0){var rGx = true;}var ju = 1;if(Math.acos(ju) >= 0){var VK = -65511;}else{oYf = 3" ascii
    $s20 = "qUk = 1;if(Math.sin(qUk) === 0){var Mq = '26104';}var _Ty = -1;if(Math.cos(_Ty) >= 0){var Pf9 = 'meager';}else{var Ju = false;}i" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}