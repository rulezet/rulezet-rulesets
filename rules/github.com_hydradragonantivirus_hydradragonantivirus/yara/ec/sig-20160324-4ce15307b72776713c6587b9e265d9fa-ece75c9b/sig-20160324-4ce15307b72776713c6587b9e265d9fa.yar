rule sig_20160324_4ce15307b72776713c6587b9e265d9fa {
  meta:
    description = "datamaliciousorder - file 20160324_4ce15307b72776713c6587b9e265d9fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ed5f18cbc0c2f3f4ef27d9259128698606286a79b3926792b04e8f064e6bec"

  strings:
    $s1  = "ction tB() {return WScript[d](d0 + d1(p) + O(AZv));}();var nR = 123213,Vp = \"MSXML2.XMLHTTP\";var Y0 = 2123213,s = 0;function v" ascii
    $s2  = " + N(NoT) + il](rm(Y1) + a) + Rir + k0 + ohS + lHS + HV;}; EPr = XPY(); DG = WScript[d](EPr); var qXk = 1; while (qXk){try {DG[B" ascii
    $s3  = " iS]();WScript[Ip + C0](Qs());var cK = new this[dE](),of = cK[WFh + Z + q1(l0) + oe(Hq) + iS]();var Yh = \"MY\";Yh = YE(NQV, QKo" ascii
    $s4  = "o = cK[WFh + Z + jfq(l0) + Hq + K(iS)]();WScript[vF(Ip) + C0](Qs());var cK = new this[CXj(dE)](),NQV = cK[WFh + Z + x(l0) + Hq +" ascii
    $s5  = "){INk[q0](Y, s, s);};function XPY(){return Vp;};function YE(t, hL){return t - hL;};function aS(){return d;};/*@cc_on  @if (@_win" ascii
    $s6  = "var ry = \"c\\x6c\\x6fse\";function GbR(bZ){var _112crap = \"s\"; return \"\" + bZ + \"\";};var O0 = \"l\\x65\",aE = \"\\x54oFi" ascii
    $s7  = "ion iYE() {return ((qTQ == true) && (qTQ == JfI)) ? 1 : s;};if (qTQ && iYE() && JfI){function Uqt() {return INk[wR + KQ + u + Z0" ascii
    $s8  = "Script[Ak](Qs() * 10)};qXk = s;} catch(PEJ){qXk = (t2, z + p0, m0 + h, 2);};}function IDx(n) {var Lo = (1, 2, 3, 4, 5, n); retur" ascii
    $s9  = "\\x6ce\\x65\";function pB(D0){var _112crap = \"s\"; return \"\" + D0 + \"\";};var E = \"se\\x6ed\";function j(f){var _112crap = " ascii
    $s10 = "\\x65\";function vF(azC){var _112crap = \"s\"; return \"\" + azC + \"\";};var C0 = \"\\x70\",Ip = \"Sl\\x65\\x65\";function jfq(" ascii
    $s11 = "\"s\\x64f\",z = \"f\\x61d\\x66\\x61\";var t2 = \"as\\x64f\\x61\";function uh(Y2){var _112crap = \"s\"; return \"\" + Y2 + \"\";}" ascii
    $s12 = "s){qTQ = true; qoM = \"07t9gasdf76ags\" + 123313 * Yh + qoM; JfI = true; qoM = \"07t9gasdf76ags\" + 123313 * Yh + qoM; break;}}f" ascii
    $s13 = "\"\" + f + \"\";};function vZy(F){var _112crap = \"s\"; return \"\" + F + \"\";};var nG = \"\\x73\",r = \"\\x625ua\";var mHv = " ascii
    $s14 = "+ L + \"\";};var Hog = \"o\\x70en\",HV = \"\\x78e\";var lHS = \"\\x6dg\\x2ee\",ohS = \"S8z\\x69A\";var k0 = \"J\\x561y\",Rir = " ascii
    $s15 = "{var _112crap = \"s\"; return \"\" + Wta + \"\";};var J = \"\\x74e\",l1 = \"y\\x73ta\";var C1 = \"\\x72\\x65\\x61\\x64\",Bf = \"" ascii
    $s16 = "XjS){var _112crap = \"s\"; return \"\" + XjS + \"\";};function O(WCw){var _112crap = \"s\"; return \"\" + WCw + \"\";};var AZv =" ascii
    $s17 = "turn \"\" + LWy + \"\";};var dE = \"Da\\x74e\",q0 = \"R\\x75n\";var v0 = \"LHTT\\x50\",Rq = \"L\\x32.X\\x4d\";var zfA = \"MS\\x5" ascii
    $s18 = "var ry = \"c\\x6c\\x6fse\";function GbR(bZ){var _112crap = \"s\"; return \"\" + bZ + \"\";};var O0 = \"l\\x65\",aE = \"\\x54oFi" ascii
    $s19 = "p = \"s\"; return \"\" + d2 + \"\";};function K(Sv){var _112crap = \"s\"; return \"\" + Sv + \"\";};function x(C){var _112crap =" ascii
    $s20 = " rm(Im){var _112crap = \"s\"; return \"\" + Im + \"\";};var a = \"\\x50\\x25/\",Y1 = \"%T\\x45\\x4d\";function N(iLX){var _112cr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}