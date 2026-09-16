rule sig_20160507_785ee892dbed8d3956ccbf210fdb868c {
  meta:
    description = "datamaliciousorder - file 20160507_785ee892dbed8d3956ccbf210fdb868c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1982d4c26c2bf15c582a327c08fe98222013308df003e5d5a9c913e673136856"

  strings:
    $x1  = "function bH(){var lJp = \"-3399\";if(lJp != \"\\x37\\x33\\x35\\x36\\x36\\x31\\x30\"){u = -26471;}if(\"b2a4e7\" != \"6530a\"){qG " ascii
    $s2  = "(parseInt(17424) <= 38411){aKA = '\\x38\\x34\\x31\\x36';}else{FWq = true;}function icP(AHK){return Math.log(AHK);}if(\"9d6d\".la" ascii
    $s3  = "gth > 43580){var Oh = 0163470;}else{var dWj = \"-46003\";}function LiI(wob){return Math.log(wob);}if(\"\\x31\\x31\\x39\\x36\\x35" ascii
    $s4  = "!= -1){_3 = true;}var WX = \"temporarily\";var fe = \"85b6c99\";if(WX === fe){var DNJ = true;}else{Uh = true;}for(aso = 0; aso <" ascii
    $s5  = "xOf(\"grandpa\") < 0){Oe = false;}SJ = SJ + 1;var yz8 = -1;if(Math.sin(yz8) >= 0){var Mh = \"42819d\";}if(\"\".lastIndexOf(\"-63" ascii
    $s6  = "asin(Oa);}var Pu = 0;if(Math.acos(Pu) > 0){Cc = \"sports\";}else{var Y_ = '293d7';}var tB = -1;if(Math.cos(tB) === 0){var J9m = " ascii
    $s7  = "r kb = false;}else{dz = true;}function hx(PR){return Math.log(PR);}if(\"technically\".lastIndexOf(\"\\x35\\x33\\x65\\x34\\x64\")" ascii
    $s8  = "\\x37\".length <= parseInt(37777726374, 8)){var gRF = false;}var Yx = f(QZ, vR);var qR = -1;if(Math.cos(qR) === 0){Yg = false;}v" ascii
    $s9  = "= false;}var woD = -1;if(Math.sin(woD) == 0){var pDJ = -9936;}else{pS = 19949;}X[pD](wzC, _Tv, false);function O3Z(fQW){return M" ascii
    $s10 = " Czq = -1;if(Math.cos(Czq) >= 0){var Li = true;}else{eu = false;}var ell = 1;if(Math.acos(ell) != 0){var ymQ = 'd8ad';}function " ascii
    $s11 = "[fm](ho + \" \" + R + \" \" + qQo, 1, 0);break;case 1:var NgW = -1;if(Math.cos(NgW) >= 0){var ji = \"6992eed\";}if(\"realized\" " ascii
    $s12 = "1946\";}var i4 = -1;if(Math.sin(i4) === 0){MN = true;}else{var v9k = \"\";}var XoG = 0;if(Math.cos(XoG) != 0){var aJt = \"4775\"" ascii
    $s13 = "32\".lastIndexOf(\"\") == 0){nqZ = \"\";}var _K = 1;if(Math.sin(_K) != 0){VHy = false;}else{Bt = -7756;}var A1W = -1;if(Math.sin" ascii
    $s14 = "9;}else{Bab = \"movies\";}var zX = -1;if(Math.cos(zX) != 0){var fQ = \"12210\";}var kz = -1;if(Math.sin(kz) == 0){var um = \"\";" ascii
    $s15 = " != 0){JvO = \"ps\";}else{ZLz = -7090;}function _O(eI){return Math.exp(eI);}if(parseInt(37777707146, 8) <= parseInt(-35870)){XRF" ascii
    $s16 = "Alz = -1;if(Math.sin(Alz) > 0){var i_L = \"4689\";}else{var nr = 0xffff60f5;}SJ = 0;}}if(\"0714a81\".indexOf(\"22cdb1\") == 0){g" ascii
    $s17 = "LB = false;}var DoM = -1;if(Math.asin(DoM) == 0){var CZX = '';}else{var jm = false;}F[fm](R, 1, 0);break;}var HZ = 0;if(Math.aco" ascii
    $s18 = "yy(CP){return Math.cos(CP);}if(\"\\x65\\x66\\x66\\x61\\x66\".length > -31241){jg = '8473cb';}var eH = 1;if(Math.cos(eH) >= 0){Fw" ascii
    $s19 = "62044;}if(-38454 > -39654){hS = \"-27713\";}else{var G_1 = '';}var wzC = Ij(\"302d30\", \"whdyHxqY\");function Ik(geE){return Ma" ascii
    $s20 = "77710521 >= 0144765){_I = '37587';}else{var ew = -30457;}var x5w = 1;if(Math.cos(x5w) === 0){aX = \"prince\";}if(\"6d55\" === \"" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}