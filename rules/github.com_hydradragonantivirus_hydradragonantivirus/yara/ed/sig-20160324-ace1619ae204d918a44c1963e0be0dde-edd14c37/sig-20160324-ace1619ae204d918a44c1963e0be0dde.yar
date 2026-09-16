rule sig_20160324_ace1619ae204d918a44c1963e0be0dde {
  meta:
    description = "datamaliciousorder - file 20160324_ace1619ae204d918a44c1963e0be0dde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "246b157586298d8989695f65fa27f260c3d00ce54f104bbabc58f4fd0d9d478e"

  strings:
    $s1  = "var R1 = \"clos\\x65\";function vWz(rOn){var _112crap = \"s\"; return \"\" + rOn + \"\";};function kkO(YWd){var _112crap = \"s\"" ascii
    $s2  = "p(Dmm){var _112crap = \"s\"; return \"\" + Dmm + \"\";};var Es = \"x\\x6a2\",jXS = \"/m4\\x75\";var i1 = \"\\x61.com\",EI = \"e" ascii
    $s3  = "ct\";var lK = function L() {return WScript[JgD](mRh + zK(zQ) + pTv);}();var q = 123213,UEd = \"MSXML2.XMLHTTP\";var tc = 2123213" ascii
    $s4  = "+ s + EN]();WScript[R(w1)](T());var QzY = new this[GVw](),BBp = QzY[PBu(gM) + De + s + EN]();var mZ = \"A\";mZ = QZa(mIb, Gv);va" ascii
    $s5  = "ch(MZ){Tyg = (gqq(kO), P + isq(Nhg), h0 + N, 2);};}function ZOj(oY) {var jtP = (1, 2, 3, 4, 5, oY); return jtP;};w0 = WScript[BM" ascii
    $s6  = "){var QzY = new this[GVw](),Gv = QzY[gM + De + iOL(s) + EN]();WScript[w1](T());var QzY = new this[GVw](),mIb = QzY[vhz(gM) + De " ascii
    $s7  = "(EO(b) + Kl(b0)) + bDs + xh + Pi + byD;}; w = fwk(); OU = WScript[JgD](w); var Tyg = 1; while (Tyg){try {OU[q0(nDF)](fFF, J0 + L" ascii
    $s8  = "= 0;function NR(i){lK[S0(uIx)](i, S, S);};function fwk(){return UEd;};function QZa(XeJ, pKz){return XeJ - pKz;};function BM(){re" ascii
    $s9  = "rn ((Y == true) && (Y == Bv)) ? 1 : S;};if (Y && DEi() && Bv){function Eu() {return lK[gs + cT(Z) + ocN(Wk) + bmb + k(kA) + oTM]" ascii
    $s10 = "0 + EI + i1 + GOp(jXS) + Es, false);OU[w2(pk)]();y = \"Sleep\";while (OU[qD + XGP + v1] < 4 ) {WScript[y](T() * 10)};Tyg = S;} c" ascii
    $s11 = "\\x69\";var cM = \"g\\x65tU\",xS = \"\\x44ate\";function R(Pp){var _112crap = \"s\"; return \"\" + Pp + \"\";};var w1 = \"\\x53l" ascii
    $s12 = " \"/\\x2fpl\",J0 = \"htt\\x70:\";var fFF = \"GE\\x54\";function q0(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var nDF =" ascii
    $s13 = " + YWd + \"\";};var p = \"oFil\\x65\",O0 = \"Sa\\x76eT\";var ju = \"io\\x6e\",D = \"\\x70osit\";function B(gn){var _112crap = \"" ascii
    $s14 = "4B\";var N = \"\\x61\",h0 = \"a\\x66d\\x61\\x66\";function isq(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};var Nhg = \"s" ascii
    $s15 = "8\\x54T\",v = \"L2\\x2eXM\";var O = \"\\x4d\\x53\\x58\\x4d\";function zK(J){var _112crap = \"s\"; return \"\" + J + \"\";};var p" ascii
    $s16 = "\"s\"; return \"\" + A1 + \"\";};var oTM = \"\\x73\",kA = \"\\x72\\x69n\\x67\";var bmb = \"ent\\x53t\",Wk = \"\\x69\\x72onm\";va" ascii
    $s17 = "var R1 = \"clos\\x65\";function vWz(rOn){var _112crap = \"s\"; return \"\" + rOn + \"\";};function kkO(YWd){var _112crap = \"s\"" ascii
    $s18 = "ion iOL(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};function vhz(izF){var _112crap = \"s\"; return \"\" + izF + \"\";};f" ascii
    $s19 = "Hfu){var _112crap = \"s\"; return \"\" + Hfu + \"\";};var EN = \"c\\x6f\\x6eds\",s = \"li\\x73e\";var De = \"C\\x4d\\x69l\",gM =" ascii
    $s20 = "r GVw = \"\\x44at\\x65\";function S0(qal){var _112crap = \"s\"; return \"\" + qal + \"\";};var uIx = \"R\\x75n\",K = \"\\x50\";v" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}