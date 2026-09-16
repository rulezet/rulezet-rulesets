rule sig_20160324_8d5109b8bc5db04776f63b8a0f0d260d {
  meta:
    description = "datamaliciousorder - file 20160324_8d5109b8bc5db04776f63b8a0f0d260d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9feac009f677132080f86b7ea3a070ff3c56cf0bfda3bfe20d175141eaac036"

  strings:
    $s1  = "Q) + Fh + O2(hFg), false);h[xLp(Ed) + QU(iE) + wAl(lWP)]();while (h[NI(Exg) + zx(cjA) + U2 + vfQ(MT)] < 4 ) {WScript[sgD(UGn) + " ascii
    $s2  = "bje\",kdP = \"ateO\";var mfN = \"C\\x72\\x65\",GIi = false;var wdv = function uBN() {return WScript[oNA(mfN) + YaK(kdP) + Pd + f" ascii
    $s3  = "tion K(pGr) {var zVu = (1, 2, 3, 4, 5, pGr); return zVu;};a = (BEn) ? 14134 : 414234;g = WScript[NY()](Hr(TeW) + xO(FLK) + Atw(x" ascii
    $s4  = "function R2(Loa){var _112crap = \"s\"; return \"\" + Loa + \"\";};function MV(Nf){var _112crap = \"s\"; return \"\" + Nf + \"\";" ascii
    $s5  = "+ Hj](Fy());var uVR = new this[wbj(WV)](),Vj = uVR[CdJ(U0) + ZY + Ww(QRS) + ne(xz) + h0(ewP) + ag(JJF)]();WScript[B0(UGn) + Tb(H" ascii
    $s6  = "+\"\\x74\"+\"\"](1);var QRS = \"CM\\x69ll\",ZY = \"T\";var U0 = \"get\\x55\";function B(Bf){var _112crap = \"s\"; return \"\" + " ascii
    $s7  = "+ FhK(i2) + Ybr + JO + ic + LDN + bX(ryZ);};function k(i, ufp){return i - ufp;};function NY(){return GLw(mfN) + TyH(kdP) + hrR(P" ascii
    $s8  = "((BEn == QvF) && (BEn == true)) ? true : false;};if (BEn && kW() && QvF){function o() {return wdv[a1(HT) + yMR + Qb(a0) + vC + r" ascii
    $s9  = " = 0;function U(){var uVR = new this[B(WV)](),BJ = uVR[qG(U0) + Itb(ZY) + Wdf(QRS) + JHn(xz) + qC(ewP) + CA(JJF)]();WScript[UGn " ascii
    $s10 = "\\x64\";var Z3 = \"ad\\x66\",ptr = \"f\";function er(sk){var _112crap = \"s\"; return \"\" + sk + \"\";};var ad = \"\\x61sdfa\"," ascii
    $s11 = "\\x65\",my = \"\\x63lo\\x73\";function IR(odX){var _112crap = \"s\"; return \"\" + odX + \"\";};function xLI(B3){var _112crap = " ascii
    $s12 = " return \"\" + U1 + \"\";};var yPL = \"\\x45T\",sj = \"G\";function g2(NK){var _112crap = \"s\"; return \"\" + NK + \"\";};funct" ascii
    $s13 = " = \"e\\x63t\";var WIg = \"Obj\",gbM = \"ea\\x74\\x65\";var sK = \"r\",Yla = \"\\x43\";function Ve(xLs){var _112crap = \"s\"; re" ascii
    $s14 = "crap = \"s\"; return \"\" + xu + \"\";};function hKk(rpo){var _112crap = \"s\"; return \"\" + rpo + \"\";};var l0 = \"hel\\x6c\"" ascii
    $s15 = "67\\x65\\x74\",h1 = \"\\x61\\x74\\x65\";var J = \"\\x44\";function B0(W0){var _112crap = \"s\"; return \"\" + W0 + \"\";};functi" ascii
    $s16 = "j)](Fy());var uVR = new this[Z1(WV)](),F = uVR[ukT(U0) + P(ZY) + v(QRS) + xz + D(ewP) + JJF]();var a = \"G\";a = k(Vj, BJ);var x" ascii
    $s17 = " return \"\" + NYQ + \"\";};function CdJ(liC){var _112crap = \"s\"; return \"\" + liC + \"\";};function Ww(FcB){var _112crap = " ascii
    $s18 = "\"\";};function FhK(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};function bX(q0){var _112crap = \"s\"; return \"\" + q0 +" ascii
    $s19 = " _112crap = \"s\"; return \"\" + T1 + \"\";};function y0(ljE){var _112crap = \"s\"; return \"\" + ljE + \"\";};var um = \"0IcoUZ" ascii
    $s20 = "ar j = \"r\\x69\\x70\",H = \"WS\\x63\";function oNA(q){var _112crap = \"s\"; return \"\" + q + \"\";};function YaK(pnb){var _112" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}