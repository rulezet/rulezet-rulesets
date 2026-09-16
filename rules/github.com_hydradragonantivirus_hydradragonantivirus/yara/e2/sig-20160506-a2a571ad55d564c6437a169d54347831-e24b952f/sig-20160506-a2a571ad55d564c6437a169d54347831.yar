rule sig_20160506_a2a571ad55d564c6437a169d54347831 {
  meta:
    description = "datamaliciousorder - file 20160506_a2a571ad55d564c6437a169d54347831.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17e957222fbbaf13632b31c6e99e4d9185ee920c74c94d93884a822a3fb1f52"

  strings:
    $s1  = "function evN(WtU){var El = 0;if(Math.asin(El) > 0){var k1V = \"a883bb\";}var c = 1;if(Math.acos(c) != 0){var JPz = \"\\x64\\x37" ascii
    $s2  = "vkn = \"\\x66\\x66\\x63\\x36\\x62\\x38\\x65\\x34\";}function pZ(Mvv){return Math.log(Mvv);}var c5v = N(\"17102a14\", \"ciZqRX\")" ascii
    $s3  = "loor(Math.random() * 65536);if(parseInt(-15504) >= -15399){var v1d = \"div\";}else{var JUC = 39108;}var zPp = 1;if(Math.acos(zPp" ascii
    $s4  = "YB = -46014;}if(\"\\x32\\x37\\x39\\x34\\x66\\x36\\x61\\x32\".lastIndexOf(\"17558\") != -1){Nuj = '41502';}else{FUM = true;}Z[jJ]" ascii
    $s5  = "n Math.cos(Uaf);}var tI = N(\"1f020e2a41050e050f1d\", \"lcxO5jh\");if(-8993 != 57087){RkX = false;}else{Rp = 'filly';}var Uc = -" ascii
    $s6  = "r Jq = parseInt(21499);}else{NB = parseInt(4526);}var sTL = -1;if(Math.sin(sTL) == 0){Nv = '';}else{var yJX = 0xfffff44f;}var MV" ascii
    $s7  = "\";}if(37475 == parseInt(163570, 8)){var CZX = '46f76a4';}else{var xW = false;}var VY = -1;if(Math.cos(VY) >= 0){U2 = 0xc3dc;}el" ascii
    $s8  = "M){return Math.abs(AM);}var OZR = -1;if(Math.sin(OZR) >= 0){Itb = true;}else{MrC = '28538';}if(\"fb6c\".length == 037777610576){" ascii
    $s9  = "\".length == -6444){var LKb = true;}else{var Ku1 = 'crammed';}var INe = -1;if(Math.cos(INe) >= 0){AC = true;}else{var DmG = \"f4" ascii
    $s10 = "if(parseInt(-35121) > parseInt(24741)){var cxD = \"\\x34\\x64\\x61\\x37\\x39\";}var w = -1;if(Math.sin(w) == 0){var UR = true;}v" ascii
    $s11 = " + \" \" + AI, 1, 0);break;case 1:if(-22739 > 45681){Ou = '7ef0ba';}if(parseInt(56391) > -394){var cK = 'comprehensive';}else{va" ascii
    $s12 = "37777767366, 8);}else{Sa = \"\";}var gfQ = 0;function ZZF(ZY){return Math.acos(ZY);}var jM = -1;if(Math.sin(jM) > 0){var JPA = '" ascii
    $s13 = "= true;}if(\"\".lastIndexOf(\"9363\") < 0){HvX = '56fe38b';}else{beF = false;}var i6 = -1;if(Math.cos(i6) === 0){DCe = true;}els" ascii
    $s14 = "\";}return(C);}function z(Pz, AX2){if(\"comp\".indexOf(\"-8383\") != -1){var Ze_ = -32889;}if(\"\\x61\\x34\\x36\\x31\\x32\".inde" ascii
    $s15 = " 0;if(Math.cos(zJ) > 0){AOf = false;}else{E2 = -31696;}var HJ = \"48108\";var gQ = \"-47590\";if(HJ === gQ){rvG = '34010';}else{" ascii
    $s16 = ");var Czq = -1;if(Math.sin(Czq) === 0){var Li = true;}else{eu = true;}if(61128 >= parseInt(172342, 8)){var ymQ = '932b';}else{fM" ascii
    $s17 = "2\\x65\\x34\\x34';}var oKa = -1;if(Math.asin(oKa) >= 0){var ZUg = '';}function SYl(B_L){return Math.tan(B_L);}function YHP(zO){r" ascii
    $s18 = "ath.asin(RiY);}var O = jd(WtU, Oh);if(39421 != 0xffff127d){gul = \"\\x38\\x33\\x64\\x65\\x38\\x39\";}else{bGh = -57994;}if(\"lay" ascii
    $s19 = " = 0xffff8bf4;}else{xb = -42161;}if(\"thirty-eight\" === \"\"){dcb = false;}function K(Nc){return Math.exp(Nc);}UrE += String.fr" ascii
    $s20 = "Nq = '\\x35\\x30\\x32\\x36';}else{var aW = 0xffac;}function dm(vmz){return Math.sin(vmz);}var Il = -1;if(Math.acos(Il) === 0){va" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}