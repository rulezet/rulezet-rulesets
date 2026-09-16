rule sig_20160506_2ebdc95a680d721ab67d5b10736bad88 {
  meta:
    description = "datamaliciousorder - file 20160506_2ebdc95a680d721ab67d5b10736bad88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd656bf8e0db97be04eca020d4e0f2649e9286a9148dc570c928d4a1fcc1ead"

  strings:
    $s1  = "function lx(L, fS6){if(\"\\x36\\x63\\x34\\x30\\x31\".length == 0120076){var tw = false;}else{lQG = false;}var Ey = 0;if(Math.aco" ascii
    $s2  = "n Math.log(Uvm);}if(\"potion\".lastIndexOf(\"\\x34\\x33\\x37\\x63\\x61\\x30\\x38\\x33\") < 0){tRo = 7071;}else{var HD = true;}va" ascii
    $s3  = ".log(FCa);}function aFY(qhS){return Math.sin(qhS);}var LV = -1;if(Math.asin(LV) == 0){var uK = '';}var U = i6();var jv = -1;if(M" ascii
    $s4  = "lse;}else{m6 = true;}var _Je = \"\";if(_Je === \"\\x35\\x36\\x61\\x65\\x64\\x33\\x65\"){var xe = \"\";}function QF6(sN3){return " ascii
    $s5  = "\" == \"\"){var Mxz = 'e2a65';}function BB(BD){return Math.log(BD);}for(hAM = 0; hAM < L.length; hAM++){function kZ(RR){return M" ascii
    $s6  = "77){Bxi = false;}else{r_Y = \"-26626\";}function SAq(ICk){return Math.log(ICk);}var hsE = 0;if(Math.asin(hsE) > 0){MKT = '-22164" ascii
    $s7  = "ion aP(_T_){return Math.log(_T_);}if(\"\" === \"7991e276\"){var h9i = \"3d015\";}if(\"\\x30\\x66\\x39\\x33\\x34\".length == 0xde" ascii
    $s8  = " Q_m = true;}var U = Math.floor(Math.random() * 65536);var Fzp = -1;if(Math.cos(Fzp) > 0){cHt = true;}var bme = \"db27a24\";var " ascii
    $s9  = "\\x62\\x39\\x31\\x66\\x34\\x39\\x31\";}var _Ok = -1;if(Math.acos(_Ok) > 0){var HU = \"-34429\";}if(\"key\".length >= -2975){var " ascii
    $s10 = "Pz = '3547';}finally{var d7 = \"58277\";}var UE = l + \"\\\\\" + U + \".\" + iI;if(parseInt(25033, 8) != 0x24cc){var qQ = -59003" ascii
    $s11 = "lse;}UC[CmG](vnX);if(parseInt(175355, 8) != 037777655351){var Td4 = '13684';}else{var i4p = false;}var cGI = -1;if(Math.sin(cGI)" ascii
    $s12 = " Math.atan(y8);}var We = 0;if(Math.sin(We) > 0){gqZ = false;}else{HM = '';}var rW = -1;if(Math.acos(rW) === 0){var seO = parseIn" ascii
    $s13 = "\";}else{a = false;}if(\"09102018\".indexOf(\"\") == -1){var Ze_ = -1360;}var ue = -1;if(Math.cos(ue) > 0){var A = \"e916\";}var" ascii
    $s14 = " == -1){sZY = true;}var Aj = 1;if(Math.cos(Aj) == 0){var Fr = true;}var XJ = \"\\x33\\x66\\x32\\x32\\x37\\x33\";if(XJ != \"\\x65" ascii
    $s15 = "med\";}var R = Yw[0];var uz = -1;if(Math.sin(uz) == 0){var TZi = 'purblind';}else{FAh = '-32050';}function wW(y0s){return Math.t" ascii
    $s16 = "ar UhN = \"-61138\";}var fIW = 1;if(Math.sin(fIW) == 0){var aWW = \"-11814\";}else{SK = \"\\x62\\x35\\x66\\x61\\x61\\x66\";}var " ascii
    $s17 = "}var MMw = J8(\"230d03153f3b17341c151d24\", \"QhpePUd\");function Qe(FEN){return Math.sin(FEN);}var s5 = -1;if(Math.asin(s5) == " ascii
    $s18 = "os(MuS) > 0){zfi = \"-24923\";}else{ne = 0xffff4a26;}var L = \"\";var Zbz = 1;if(Math.cos(Zbz) != 0){GPd = false;}if(040631 <= -" ascii
    $s19 = "r ZV = false;}else{BU = true;}var ytW = -1;if(Math.sin(ytW) == 0){WI = '\\x65\\x66\\x61\\x65\\x65\\x37';}else{var byj = \"49629" ascii
    $s20 = "){fh = '331316';}else{var EZg = -39876;}if(I == J8(\"3b63\", \"v9Rnd7w\")){var ACt = 0;if(Math.cos(ACt) > 0){JAw = false;}var aY" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}