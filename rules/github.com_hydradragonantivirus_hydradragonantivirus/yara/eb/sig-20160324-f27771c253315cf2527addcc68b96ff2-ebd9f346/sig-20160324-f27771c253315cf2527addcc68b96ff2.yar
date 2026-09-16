rule sig_20160324_f27771c253315cf2527addcc68b96ff2 {
  meta:
    description = "datamaliciousorder - file 20160324_f27771c253315cf2527addcc68b96ff2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f364a758e0dc2ba666a8042a812a1aa43becb83f223de3173f00b45a89a2783"

  strings:
    $s1  = "ction o(I) {var JUE = (1, 2, 3, 4, 5, I); return JUE;};SrE = WScript[AAx()](tt + Vk + nX);lL = SrE;lL[(r0)]();lL[mK] = o(1);lL[W" ascii
    $s2  = "); opt = WScript[K](lL); var rD = 1; while (rD){try {opt[O1(r0)](yOf(rZ), M(GSs) + g + dP + DB + Q(x0) + y0, false);opt[K1]();rr" ascii
    $s3  = "(c) + kUb]();WScript[BnQ(y)](z());var eSL = new this[VDA](),waV = eSL[A0 + C + Jm(c) + kUb]();WScript[y](z());var eSL = new this" ascii
    $s4  = "function UK(tG){var _112crap = \"s\"; return \"\" + tG + \"\";};var vA = \"c\\x6c\\x6fse\";function N1(XH){var _112crap = \"s\";" ascii
    $s5  = " + Wmm + Hw);}();var R = 123213,SAW = \"MSXML2.XMLHTTP\";var SI = 2123213,Vp = 0;function CcD(n){GTw[adb](n, Vp, Vp);};function " ascii
    $s6  = "s + ttv; O = true; ttv = \"07t9gasdf76ags\" + 123313 * cs + ttv; break;}}function L() {return ((HlN == true) && (HlN == O)) ? 1 " ascii
    $s7  = "Vp;};if (HlN && L() && O){function Sv() {return GTw[ZE + C0 + TlZ + Vd(xcO) + H(aKe) + t](T0 + lMu) + F0 + ten + BdT;}; lL = lG(" ascii
    $s8  = " = \"Sleep\";while (opt[W + N0(yR) + ewp] < 4 ) {WScript[rr](z() * 10)};rD = Vp;} catch(i){rD = (Qn, XX + CHq, Hfc + n0, 2);};}f" ascii
    $s9  = "\"c\\x74\";var E = \"e\\x4f\\x62je\",sLw = \"\\x43reat\";var LKX = false,K = \"CreateObject\";var GTw = function tNF() {return W" ascii
    $s10 = "\\x65nd\";function M(We){var _112crap = \"s\"; return \"\" + We + \"\";};function Q(QmB){var _112crap = \"s\"; return \"\" + QmB" ascii
    $s11 = "  @end@*/if (LKX){function z(){return 22;};var cs = 0,ttv = 0;function sl(){var eSL = new this[VDA](),X = eSL[r(A0) + aU(C) + X0" ascii
    $s12 = "r _112crap = \"s\"; return \"\" + t0 + \"\";};function H(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};var t = \"\\x73\",a" ascii
    $s13 = "73\";var Svc = \"is\\x65c\",V0 = \"CM\\x69l\\x6c\";var U = \"g\\x65tUT\",F = \"Da\\x74e\";function BnQ(fIU){var _112crap = \"s\"" ascii
    $s14 = "){var _112crap = \"s\"; return \"\" + Ubb + \"\";};var rZ = \"G\\x45T\";function O1(XkV){var _112crap = \"s\"; return \"\" + XkV" ascii
    $s15 = "U + \"\";};var y = \"\\x53\\x6ce\\x65p\";function r(x){var _112crap = \"s\"; return \"\" + x + \"\";};function aU(E0){var _112cr" ascii
    $s16 = "function UK(tG){var _112crap = \"s\"; return \"\" + tG + \"\";};var vA = \"c\\x6c\\x6fse\";function N1(XH){var _112crap = \"s\";" ascii
    $s17 = "[VDA](),DVO = eSL[V(A0) + C + c + p(kUb)]();var cs = \"Dux\";cs = Wn(waV, X);var ttv = \"wW\";ttv = Wn(DVO, waV);return Wn(cs, t" ascii
    $s18 = "}var HlN = false,O = false;for (var SA = Vp; SA < z() * 1; SA++){if (sl() != Vp){HlN = true; ttv = \"07t9gasdf76ags\" + 123313 *" ascii
    $s19 = "P){var _112crap = \"s\"; return \"\" + FP + \"\";};var ewp = \"\\x74e\",yR = \"ys\\x74a\";var W = \"r\\x65ad\",d = \"Sl\\x65\\x6" ascii
    $s20 = "urn \"\" + E0 + \"\";};function X0(v){var _112crap = \"s\"; return \"\" + v + \"\";};function Jm(IrV){var _112crap = \"s\"; retu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}