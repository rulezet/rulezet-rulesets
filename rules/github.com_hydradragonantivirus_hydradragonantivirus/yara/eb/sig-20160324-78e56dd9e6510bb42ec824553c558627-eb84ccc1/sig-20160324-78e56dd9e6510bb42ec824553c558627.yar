rule sig_20160324_78e56dd9e6510bb42ec824553c558627 {
  meta:
    description = "datamaliciousorder - file 20160324_78e56dd9e6510bb42ec824553c558627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "007426c1e2f1148ebe3a77c7c4ac66277e7887271060b0f6a85f37f3e7890c6c"

  strings:
    $s1  = "\",AVv = T[\"\"+\"\\x63\"+\"har\"+\"\\x41\"+\"t\"](0);var g = \"Cre\\x61\",N = false;var VZp = function Nbg() {return WScript[iI" ascii
    $s2  = "z)]();WScript[u(hO) + RJu(wu)](uQT());var OnS = new this[ZNc(DN)](),UA = OnS[hB(uqG) + zX + E0(rt) + v1(q1) + KF + FbF(cj) + Ru " ascii
    $s3  = "+ SR(j0) + N1(c2) + lRf;}; dyM = yhr(); JW = WScript[X(g) + AVv + c0(J) + NG(c)](dyM); var w = true; while (w){try {JW[q3](TI(dh" ascii
    $s4  = "on Z(LM) {var Jtk = (1, 2, 3, 4, 5, LM); return Jtk;};LLi = (H) ? 14134 : 414234;w0 = WScript[Rug()](ai(t) + qM(n) + K1 + s3(f0)" ascii
    $s5  = "oAB) + SPD(Z1) + M0(s1) + LyI;};function zg(GhT, r){return GhT - r;};function Rug(){return g + AZ(AVv) + M(J) + c;};/*@cc_on  @i" ascii
    $s6  = "\"07t9gasdf76ags\" + 123313 * LLi + fk; break;}}function tLI() {return ((H == q) && (H == true)) ? true : false;};if (H && tLI()" ascii
    $s7  = "\\x50\\x25/\",UB = \"%T\\x45\";function AD(X1){var _112crap = \"s\"; return \"\" + X1 + \"\";};function lqz(Dv){var _112crap = " ascii
    $s8  = "function ZE(HZ){var _112crap = \"s\"; return \"\" + HZ + \"\";};function bg(jd0){var _112crap = \"s\"; return \"\" + jd0 + \"\";" ascii
    $s9  = "\\x6fs\\x65\",hIl = \"c\\x6c\";function d0(Fx){var _112crap = \"s\"; return \"\" + Fx + \"\";};function Etz(i2){var _112crap = " ascii
    $s10 = "\\x63\"+\"har\"+\"\\x41\"+\"t\"](3);var s0 = \"Ru\";function j(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function O(nT" ascii
    $s11 = "{var _112crap = \"s\"; return \"\" + I0 + \"\";};function zN(Bl){var _112crap = \"s\"; return \"\" + Bl + \"\";};var E = \"Mpfn" ascii
    $s12 = "\"s\"; return \"\" + nT + \"\";};function uz(nxs){var _112crap = \"s\"; return \"\" + nxs + \"\";};var BAT = \"1meNr\",B = \"ll" ascii
    $s13 = " = \"htt\";function TI(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};var dh = \"\\x47E\\x54\";function lD(CE){var _112crap" ascii
    $s14 = "+ \"\";};function DB(hDy){var _112crap = \"s\"; return \"\" + hDy + \"\";};function lY(Og){var _112crap = \"s\"; return \"\" + O" ascii
    $s15 = "\"\"+\"\\x63\"+\"har\"+\"\\x41\"+\"t\"](2),g0 = \"Sh\";var os = \"pt\\x2e\",i = \"\\x57Sc\\x72i\";function iI(Ol){var _112crap =" ascii
    $s16 = "ction UrK(LO){var _112crap = \"s\"; return \"\" + LO + \"\";};function SPD(xq){var _112crap = \"s\"; return \"\" + xq + \"\";};f" ascii
    $s17 = "function ZE(HZ){var _112crap = \"s\"; return \"\" + HZ + \"\";};function bg(jd0){var _112crap = \"s\"; return \"\" + jd0 + \"\";" ascii
    $s18 = "), nWn(atE) + rW(to) + kH(Ql) + IG + Fp + QyF(Z2) + ox + Vmg(A) + Zb, false);JW[oI + dxQ]();while (JW[E2(K0) + jTn] < 4 ) {WScri" ascii
    $s19 = "var _112crap = \"s\"; return \"\" + oO + \"\";};function X(isu){var _112crap = \"s\"; return \"\" + isu + \"\";};function c0(FS)" ascii
    $s20 = "\"\" + llM + \"\";};function I1(LL){var _112crap = \"s\"; return \"\" + LL + \"\";};var f = \"mszvV\",Zz = f[\"\"+\"\\x63\"+\"ha" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}