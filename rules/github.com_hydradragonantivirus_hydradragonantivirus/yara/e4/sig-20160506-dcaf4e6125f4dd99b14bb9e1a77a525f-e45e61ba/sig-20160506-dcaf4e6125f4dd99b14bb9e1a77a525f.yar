rule sig_20160506_dcaf4e6125f4dd99b14bb9e1a77a525f {
  meta:
    description = "datamaliciousorder - file 20160506_dcaf4e6125f4dd99b14bb9e1a77a525f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3778edce293f07fca8e110cf981a18c795ee288d0b4ba1ea70ebd80dd90d3319"

  strings:
    $x1  = "function uhw(N0b){var A = -1;if(Math.asin(A) === 0){var PMR = false;}else{var Xma = '44985';}if(-45382 >= -10666){D1 = true;}els" ascii
    $s2  = ";}if(\"\\x38\\x37\\x33\\x39\".lastIndexOf(\"29711\") == -1){S45 = '\\x35\\x37\\x33\\x31\\x32';}function FFA(Ua){return Math.log(" ascii
    $s3  = "yr = -19716;}else{RdQ = '';}if(\"sneak\".indexOf(\"users\") != -1){var _qT = \"\\x34\\x31\\x35\\x35\\x38\";}else{gK = \"96775\";" ascii
    $s4  = "\" != \"compressed\"){var iGC = \"\\x61\\x32\\x64\\x37\\x63\\x30\\x62\";}var opM = -1;if(Math.sin(opM) >= 0){UM = parseInt(29263" ascii
    $s5  = "ath.sin(s2) === 0){eg = true;}if(\"-22632\".lastIndexOf(\"\\x61\\x33\\x31\\x36\\x30\\x61\") == 0){var PQ4 = -54469;}var a_r = 0;" ascii
    $s6  = "63704';}else{var zVS = 35489;}var _ = ic(KZ, THZ);if(\"treating\" === \"pounce\"){var vI = parseInt(27187);}var o = -1;if(Math.s" ascii
    $s7  = "r FEN = -1;if(Math.cos(FEN) >= 0){var RF = 0xffff6b9c;}else{NN = 0xf6da;}if(-62773 === parseInt(40623)){J_ = -48044;}if(\"\\x65" ascii
    $s8  = "stIndexOf(\"\") == -1){var jUF = '\\x37\\x65\\x35\\x31\\x64\\x63';}function iTk(CKj){return Math.floor(CKj);}var hw_ = -1;if(Mat" ascii
    $s9  = "\") == -1){var A8k = \"-8235\";}else{var s6y = true;}var ihU = 0;if(Math.sin(ihU) > 0){pnS = '';}function lKl(xF){return Math.ab" ascii
    $s10 = "eInt(37777601611, 8);}if(\"\".lastIndexOf(\"-36411\") != -1){Ljk = false;}var Wg = \"\";function rZ(Ic){return Math.cos(Ic);}var" ascii
    $s11 = "f0bd\"){var RtC = -32229;}else{bmE = -53452;}var ut = 0;if(Math.sin(ut) >= 0){var b_P = 0x2275;}else{var cd = \"\\x37\\x33\\x36" ascii
    $s12 = " \"salmon\";}function oo3(GlJ){return Math.atan(GlJ);}var VGh = Sw(\"25200a0207\", \"FLeqbDv\");var D8J = -1;if(Math.cos(D8J) > " ascii
    $s13 = ";}var DZV = 0;if(Math.sin(DZV) == 0){var e3 = true;}else{w = true;}var fR = \"\";function Yz(rf){return Math.ceil(rf);}var IK = " ascii
    $s14 = "9\\x33\\x37';}var YYF = -1;if(Math.sin(YYF) >= 0){var oI = '-33132';}else{var HJ0 = \"58122\";}if(30317 <= 42670){zKd = '-43486'" ascii
    $s15 = "(Math.cos(D8) === 0){var Ud = \"-49087\";}else{Fo = \"-9635\";}if(\"\\x32\\x38\\x31\\x34\\x31\".indexOf(\"\\x30\\x34\\x33\\x36" ascii
    $s16 = "f(Math.sin(giH) == 0){var MT = '\\x66\\x64\\x30\\x66\\x66';}else{Q = -48307;}if(0xf92f != parseInt(44454)){var QwB = 0xfffff16b;" ascii
    $s17 = "nction by(DYX){return Math.atan(DYX);}var lnM = -1;if(Math.sin(lnM) == 0){Ctj = true;}var OJ = \"-25645\";var px = \"-60648\";if" ascii
    $s18 = "YJ = 'ill-omened';}if(\"\\x62\\x39\\x39\\x34\\x36\".length === 0131543){var kpD = 25965;}else{_u = -3098;}var THA = 0;if(Math.co" ascii
    $s19 = "19';}function kx(jA){return Math.cos(jA);}var aX = Sw(\"2d082b\", \"IdGO51s\");}else{var xjJ = -1;if(Math.acos(xjJ) == 0){var sc" ascii
    $s20 = " = Sw(\"202042135d192237275e074b\", \"RE1c2wQ\");var Wn = -1;if(Math.sin(Wn) > 0){var tD = '\\x31\\x30\\x65\\x62\\x64\\x64';}els" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}