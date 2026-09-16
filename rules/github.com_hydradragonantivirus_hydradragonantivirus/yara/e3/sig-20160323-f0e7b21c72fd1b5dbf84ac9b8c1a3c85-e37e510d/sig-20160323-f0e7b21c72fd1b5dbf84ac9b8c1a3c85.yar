rule sig_20160323_f0e7b21c72fd1b5dbf84ac9b8c1a3c85 {
  meta:
    description = "datamaliciousorder - file 20160323_f0e7b21c72fd1b5dbf84ac9b8c1a3c85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0be9f30a14d73014cf4a05d8f7352cf5ef1b91e9d13152aeb6ed801d7d107fb2"

  strings:
    $s1  = "zzn(C1) + O1(daB)]();WScript[EI + M(Ka)](eZ());var qQH = new this[IEZ + a + gw(W0)](),EK = qQH[O0 + ju(rIB) + iBW(Qjy) + Dld(zXc" ascii
    $s2  = ") + C1 + nxB(daB)]();WScript[EI + jUq(Ka)](eZ());var qQH = new this[EkS(IEZ) + sZW(a) + cx(W0)](),ixk = qQH[w(O0) + R(rIB) + fZ(" ascii
    $s3  = "function pg(lTa){var _112crap = \"s\"; return \"\" + lTa + \"\";};var Gh = \"c\\x6co\\x73\\x65\";function N1(gEK){var _112crap =" ascii
    $s4  = ", S); return vqL;};O = (A) ? 14134 : 414234;nNP = WScript[m()](gEk(SbU) + uy(q3) + cdh + ztv(iw));Uqt = nNP;P = (k) ? O : P;Uqt[" ascii
    $s5  = "turn WScript[Y0(CmG) + n + EJw(zAo) + em + AU](zsl + dG(dR) + Mi(cKh) + T0(PwF));}();function Lc(Db){VIg[pi(DJ) + j0](Db, 0, 0);" ascii
    $s6  = "74\"+\"\"](1),O0 = \"get\";function aB(AAx){var _112crap = \"s\"; return \"\" + AAx + \"\";};function S1(P0){var _112crap = \"s" ascii
    $s7  = " TdM[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"](0);function jV(xII){var _112crap = \"s\"; return \"\" + xII + \"\";};var N0 = \"GET" ascii
    $s8  = "};function dX(){return C + rOJ(v0) + C0(A0) + yb(Zr) + EoE(I) + z0(Y1);};function ojN(S0, T){return S0 - T;};function m(){return" ascii
    $s9  = "7t9gasdf76ags\" + 123313 * O + P; break;}}function jC() {return ((A == k) && (A == true)) ? true : false;};if (A && jC() && k){f" ascii
    $s10 = "fzp + V + SB(Ok0), false);b[IuC(TH)]();while (b[D1(CA) + oWw(ezl) + oN(BHY)] < 4 ) {WScript[xfn(EI) + P1(Ka)](eZ() * 10)};xc = f" ascii
    $s11 = "\\x65at\";function urf(qiK){var _112crap = \"s\"; return \"\" + qiK + \"\";};function g(BW){var _112crap = \"s\"; return \"\" + " ascii
    $s12 = "\"s\"; return \"\" + Wa + \"\";};function Qmb(EDA){var _112crap = \"s\"; return \"\" + EDA + \"\";};function qTA(kg){var _112cra" ascii
    $s13 = "\" + Djd + \"\";};var AWu = \"%/\",wS = \"\\x25TE\\x4d\\x50\";function ZlC(t){var _112crap = \"s\"; return \"\" + t + \"\";};fun" ascii
    $s14 = "\"on\",j1 = \"\\x74i\";var xva = \"p\\x6fsi\";function y0(q4){var _112crap = \"s\"; return \"\" + q4 + \"\";};function jfq(qZ){v" ascii
    $s15 = "n \"\" + Yy + \"\";};function jLZ(n0){var _112crap = \"s\"; return \"\" + n0 + \"\";};var YN = \"4Wv\",wFl = \"6e6iIP\";var XO =" ascii
    $s16 = "nction xyV(n1){var _112crap = \"s\"; return \"\" + n1 + \"\";};function q0(M2){var _112crap = \"s\"; return \"\" + M2 + \"\";};f" ascii
    $s17 = "function pg(lTa){var _112crap = \"s\"; return \"\" + lTa + \"\";};var Gh = \"c\\x6co\\x73\\x65\";function N1(gEK){var _112crap =" ascii
    $s18 = "Qjy) + xik(zXc) + lfa(C1) + gZ(daB)]();var O = \"K\";O = ojN(EK, yZo);var P = \"jIu\";P = ojN(ixk, EK);return ojN(O, P);}var A =" ascii
    $s19 = "65\\x6ed\";function pES(ep){var _112crap = \"s\"; return \"\" + ep + \"\";};function FE(uV){var _112crap = \"s\"; return \"\" + " ascii
    $s20 = "f){var _112crap = \"s\"; return \"\" + Ydf + \"\";};function FYT(W){var _112crap = \"s\"; return \"\" + W + \"\";};var Ez = \"Pr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}