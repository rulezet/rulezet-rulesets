rule sig_20160324_bee52936ec9d20d76cb9a2d8bdda617c {
  meta:
    description = "datamaliciousorder - file 20160324_bee52936ec9d20d76cb9a2d8bdda617c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2907d62e2fd82d25263793d01d070635f4a7bcd2c6592be8dbe664faa2ed734b"

  strings:
    $s1  = "var E = \"\\x63los\\x65\";function n(zY){var _112crap = \"s\"; return \"\" + zY + \"\";};function D2(KO){var _112crap = \"s\"; r" ascii
    $s2  = " = function i() {return WScript[iht](C + UvA + Mtl);}();var IDu = 123213,D = \"MSXML2.XMLHTTP\";var x = 2123213,MWI = 0;function" ascii
    $s3  = "();WScript[Oi(ExJ)](eKA());var aD = new this[T](),F = aD[LG(qr) + ta + Frm(ISE) + JCj]();var Ude = \"w\";Ude = g(tIj, O);var cSM" ascii
    $s4  = "){S = (r1 + oS, e0(cUe) + uW, bpc(sds) + im, 2);};}function q(Hjb) {var TwN = (1, 2, 3, 4, 5, Hjb); return TwN;};q0 = WScript[Ip" ascii
    $s5  = "w this[T](),O = aD[qr + ta + ISE + JCj]();WScript[ExJ](eKA());var aD = new this[HXV(T)](),tIj = aD[O0(qr) + ta + ISE + IFi(JCj)]" ascii
    $s6  = " + j + j0](ea + OAW) + P + UQ + Wm(yS);}; OOp = L(); Pt = WScript[iht](OOp); var S = 1; while (S){try {Pt[i3](I, Wdf(f) + xu + h" ascii
    $s7  = "(r){Lgx[knu](r, MWI, MWI);};function L(){return D;};function g(Nf, bZS){return Nf - bZS;};function IpW(){return iht;};/*@cc_on  " ascii
    $s8  = "on sNA() {return ((ud == true) && (ud == wzz)) ? 1 : MWI;};if (ud && sNA() && wzz){function QQ() {return Lgx[QG + wiy + r0 + vDM" ascii
    $s9  = " + iEe + qI(spe) + d1(X), false);Pt[j1]();i0 = \"Sleep\";while (Pt[b + f0 + MX] < 4 ) {WScript[i0](eKA() * 10)};S = MWI;} catch(" ascii
    $s10 = "var iEe = \"\\x2e\\x63om\\x2f\",h = \"pr\\x65z\";var xu = \"//b\\x79\",f = \"h\\x74\\x74p:\";var I = \"GE\\x54\";function DtS(y)" ascii
    $s11 = " \"Re\\x73p\";function W(OS){var _112crap = \"s\"; return \"\" + OS + \"\";};var Sk = \"wr\\x69te\",wJJ = \"\\x74ype\";var Y0 = " ascii
    $s12 = "{ud = true; cSM = \"07t9gasdf76ags\" + 123313 * Ude + cSM; wzz = true; cSM = \"07t9gasdf76ags\" + 123313 * Ude + cSM; break;}}fu" ascii
    $s13 = "var E = \"\\x63los\\x65\";function n(zY){var _112crap = \"s\"; return \"\" + zY + \"\";};function D2(KO){var _112crap = \"s\"; r" ascii
    $s14 = "nction qNM(H){var _112crap = \"s\"; return \"\" + H + \"\";};var Qo = \"\\x61m\",oX = \"\\x2eSt\\x72\\x65\";var OP = \"ADO\\x44B" ascii
    $s15 = " \"uWb\";cSM = g(F, tIj);return g(Ude, cSM);}var ud = false,wzz = false;for (var OM = MWI; OM < eKA() * 1; OM++){if (MsO() != MW" ascii
    $s16 = "ady\",y0 = \"\\x53le\\x65p\";var j1 = \"\\x73e\\x6ed\";function Wdf(U){var _112crap = \"s\"; return \"\" + U + \"\";};function q" ascii
    $s17 = "\"; return \"\" + y + \"\";};var i3 = \"o\\x70en\";function Wm(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};var yS = \"" ascii
    $s18 = "B + \"\";};function LG(xb){var _112crap = \"s\"; return \"\" + xb + \"\";};function Frm(d){var _112crap = \"s\"; return \"\" + d" ascii
    $s19 = "1){var _112crap = \"s\"; return \"\" + F1 + \"\";};var im = \"f\\x61\",sds = \"\\x61fd\\x61\";function e0(D0){var _112crap = \"s" ascii
    $s20 = "l\\x69\\x73e\",clm = \"\\x43Mil\";var i2 = \"\\x67et\\x55T\",hhI = \"\\x44ate\";function Oi(kQR){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}