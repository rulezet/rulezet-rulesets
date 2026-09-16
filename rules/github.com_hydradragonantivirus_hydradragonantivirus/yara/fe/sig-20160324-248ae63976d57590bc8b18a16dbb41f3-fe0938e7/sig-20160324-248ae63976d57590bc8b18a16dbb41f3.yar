rule sig_20160324_248ae63976d57590bc8b18a16dbb41f3 {
  meta:
    description = "datamaliciousorder - file 20160324_248ae63976d57590bc8b18a16dbb41f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd41e5d7ce356fbe05dc4da2f021ea995ff954bfaef3ca9d9b663053e40c19ac"

  strings:
    $s1  = "function XMn(T){var _112crap = \"s\"; return \"\" + T + \"\";};var Dii = \"\\x65\",Wy = \"cl\\x6fs\";var Yz = \"\\x6c\\x65\",aY " ascii
    $s2  = "O](b());var yE = new this[CmP](),Bp = yE[v + uJf + xMq + qDX]();WScript[PO](b());var yE = new this[CmP](),V = yE[v + uJf + xMq +" ascii
    $s3  = "ction b(){return 22;};var tFF = 0,Fe = 0;function K(){var yE = new this[CmP](),olP = yE[C(v) + uJf + xMq + alR(qDX)]();WScript[P" ascii
    $s4  = "{try {m[pYO](R, X0 + BGl + ES + Ah + S + G + VG, false);m[TO]();lj = \"Sleep\";while (m[XxR + Fe0(W) + xp] < 4 ) {WScript[lj](b(" ascii
    $s5  = "eOb\\x6a\";var GZv = \"Cr\\x65at\",Eu = false;var D = \"CreateObject\",OZi = function Ys() {return WScript[D](b1 + CB + cO);}();" ascii
    $s6  = "OZi[y + hQv + Ezp + X + UD + Sqf](SAm + Qa) + Qe(qE) + lmO + Ad(PZi) + Mu;}; aH = UO(); m = WScript[D](aH); var l = 1; while (l)" ascii
    $s7  = "+ 123313 * tFF + Fe; break;}}function u() {return ((x == true) && (x == P)) ? 1 : yFt;};if (x && u() && P){function Y() {return " ascii
    $s8  = "\\x6c\\x65\\x65p\";function C(gfK){var _112crap = \"s\"; return \"\" + gfK + \"\";};function alR(rT){var _112crap = \"s\"; retur" ascii
    $s9  = "e\\x72\",BGl = \":\\x2f\\x2fk\";var X0 = \"h\\x74\\x74p\",R = \"G\\x45T\";function l0(m2){var _112crap = \"s\"; return \"\" + m2" ascii
    $s10 = "= yFt; dN < b() * 1; dN++){if (K() != yFt){x = true; Fe = \"07t9gasdf76ags\" + 123313 * tFF + Fe; P = true; Fe = \"07t9gasdf76ag" ascii
    $s11 = " \"\\x6fpe\\x6e\";function Qe(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";};function Ad(sp){var _112crap = \"s\"; return " ascii
    $s12 = "function Em(qn){var _112crap = \"s\"; return \"\" + qn + \"\";};var sXx = \"sd\\x66\",Ex = \"\\x66a\\x64\\x66a\";var rY0 = \"a" ascii
    $s13 = "* 10)};l = yFt;} catch(MnG){l = (rY0, Ex + Em(sXx), Og + PjF, 2);};}function Nh(Y0) {var CkN = (1, 2, 3, 4, 5, Y0); return CkN;}" ascii
    $s14 = " _112crap = \"s\"; return \"\" + duJ + \"\";};var i = \"r\\x65am\",e = \"B.\\x53t\";var ojj = \"A\\x44O\\x44\",PjF = \"\\x66a\";" ascii
    $s15 = "function XMn(T){var _112crap = \"s\"; return \"\" + T + \"\";};var Dii = \"\\x65\",Wy = \"cl\\x6fs\";var Yz = \"\\x6c\\x65\",aY " ascii
    $s16 = ";function Fe0(sLJ){var _112crap = \"s\"; return \"\" + sLJ + \"\";};var xp = \"\\x65\",W = \"\\x79st\\x61t\";var XxR = \"rea\\x6" ascii
    $s17 = "sRE = \"\\x53ave\";function tZ(yb){var _112crap = \"s\"; return \"\" + yb + \"\";};var P0 = \"\\x69o\\x6e\",qRh = \"\\x70os\\x69" ascii
    $s18 = " = 123213,ZOA = \"MSXML2.XMLHTTP\";var OVK = 2123213,yFt = 0;function YrG(U){OZi[F](U, yFt, yFt);};function UO(){return ZOA;};fu" ascii
    $s19 = "tion amg(Hn, ah){return Hn - ah;};function AFd(){return D;};/*@cc_on  @if (@_win32 || @_win64)    Eu = true;  @end@*/if (Eu){fun" ascii
    $s20 = " qDX]();var tFF = \"q\";tFF = amg(Bp, olP);var Fe = \"b0\";Fe = amg(V, Bp);return amg(tFF, Fe);}var x = false,P = false;for (var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}