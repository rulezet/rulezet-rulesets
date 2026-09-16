rule sig_20160324_75d5c56b52175a4b5503d27393b31ad2 {
  meta:
    description = "datamaliciousorder - file 20160324_75d5c56b52175a4b5503d27393b31ad2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7c2f8837b71eeeccc94793869453c9336244c43b1cae4695b7dfa6d8653c4c3"

  strings:
    $s1  = "eateObject\";var J = function p() {return WScript[X0](fGU + Nj(lxH) + yZ);}();var RZ = 123213,xnm = \"MSXML2.XMLHTTP\";var Q = 2" ascii
    $s2  = "();WScript[vqO](bva());var VY = new this[v0](),j = VY[Gi + mA(HQj) + lM(dJw) + m]();var v = \"O\";v = L(ra, y);var Ew = \"kRJ\";" ascii
    $s3  = " + HU(GDG) + hQ + jnu + U + Ao;}; fD = MWD(); ha = WScript[X0](fD); var Yq = 1; while (Yq){try {ha[ZgF](FG, n0(l) + u0(iTX) + yz" ascii
    $s4  = "atch(SZz){Yq = (z + iy, ZW + kL, z0 + p0, 2);};}function Kj(X) {var h = (1, 2, 3, 4, 5, X); return h;};bS = WScript[o()](ET(Z0) " ascii
    $s5  = " + Ze(DmD) + Ytr(n) + qQa + r0, false);ha[kFG]();H = \"Sleep\";while (ha[TPR + CfL(I0)] < 4 ) {WScript[H](bva() * 10)};Yq = PX;}" ascii
    $s6  = "var VY = new this[v0](),y = VY[Gi + HQj + dJw + m]();WScript[vqO](bva());var VY = new this[v0](),ra = VY[Gi + HQj + JV(dJw) + m]" ascii
    $s7  = "213,PX = 0;function Knc(mP){J[twE](mP, PX, PX);};function MWD(){return xnm;};function L(I, f){return I - f;};function o(){return" ascii
    $s8  = "function W(TFw){var _112crap = \"s\"; return \"\" + TFw + \"\";};var de = \"clo\\x73e\";function Xx(ceb){var _112crap = \"s\"; r" ascii
    $s9  = "& (t == eI)) ? 1 : PX;};if (t && r() && eI){function Gkw() {return J[GiP + wYq(Q0) + eK + FmV(vdU) + jw(Vy) + MDc](mb(Tbb) + In)" ascii
    $s10 = "t9gasdf76ags\" + 123313 * v + Ew; eI = true; Ew = \"07t9gasdf76ags\" + 123313 * v + Ew; break;}}function r() {return ((t == true" ascii
    $s11 = "(YmI){var _112crap = \"s\"; return \"\" + YmI + \"\";};function u0(xxe){var _112crap = \"s\"; return \"\" + xxe + \"\";};functio" ascii
    $s12 = " _112crap = \"s\"; return \"\" + XZ + \"\";};function Ytr(qg){var _112crap = \"s\"; return \"\" + qg + \"\";};var r0 = \"\\x73\"" ascii
    $s13 = "function ET(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};var LKW = \"e\\x61m\",iNO = \"B\\x2e\\x53t\\x72\";var Z0 = \"A" ascii
    $s14 = "function W(TFw){var _112crap = \"s\"; return \"\" + TFw + \"\";};var de = \"clo\\x73e\";function Xx(ceb){var _112crap = \"s\"; r" ascii
    $s15 = "\"LHTT\\x50\",G = \"L2\\x2e\\x58M\";var dCj = \"M\\x53\\x58\\x4d\";function Nj(u){var _112crap = \"s\"; return \"\" + u + \"\";}" ascii
    $s16 = "112crap = \"s\"; return \"\" + o0 + \"\";};var Tdd = \"t\\x69\\x6fn\",Im = \"pos\\x69\";function j1(z1){var _112crap = \"s\"; re" ascii
    $s17 = "n \"\" + J0 + \"\";};function mA(iZf){var _112crap = \"s\"; return \"\" + iZf + \"\";};function lM(HCQ){var _112crap = \"s\"; re" ascii
    $s18 = "bb = \"%TEM\\x50\";function wYq(G0){var _112crap = \"s\"; return \"\" + G0 + \"\";};function FmV(aBU){var _112crap = \"s\"; retu" ascii
    $s19 = " L(j, ra);return L(v, Ew);}var t = false,eI = false;for (var bmA = PX; bmA < bva() * 1; bmA++){if (g() != PX){t = true; Ew = \"0" ascii
    $s20 = "4a\\x7a\\x73S\",hQ = \"\\x7aOYh\";var GDG = \"\\x654kC\\x71\";function mb(eV){var _112crap = \"s\"; return \"\" + eV + \"\";};va" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}