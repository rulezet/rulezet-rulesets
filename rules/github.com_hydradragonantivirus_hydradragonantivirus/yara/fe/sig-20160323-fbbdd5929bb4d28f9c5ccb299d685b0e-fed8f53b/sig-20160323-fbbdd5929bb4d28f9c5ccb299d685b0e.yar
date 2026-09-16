rule sig_20160323_fbbdd5929bb4d28f9c5ccb299d685b0e {
  meta:
    description = "datamaliciousorder - file 20160323_fbbdd5929bb4d28f9c5ccb299d685b0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa59e5a903f958c86fbae173c3a23686ab804cf327e2e1ca94f8ac871dca734b"

  strings:
    $s1  = "f) + kf + w4(p), false);SC[xab(H2)]();while (SC[G1 + gb + P1 + i1] < 4 ) {WScript[fUk + kn(Jve) + JAD](t() * 10)};OB = false;} c" ascii
    $s2  = "L = (1, 2, 3, 4, 5, w); return KFL;};ryt = (Tjx) ? 14134 : 414234;M0 = WScript[k()](z2(P4) + z1 + Sy + XhL(rbl));w0 = M0;WI = (y" ascii
    $s3  = "[gXt(VU) + STY(jN) + XwU(P) + v0]();WScript[h0(fUk) + OOb(Jve) + hE(JAD)](t());var K = new this[U + HMn(m)](),Y = K[Qyc(VU) + ld" ascii
    $s4  = "h(jN) + M1(P) + v0]();WScript[fUk + Iq(Jve) + Z(JAD)](t());var K = new this[K0(U) + H(m)](),r0 = K[nO(VU) + jN + FWe(P) + oys(v0" ascii
    $s5  = "function e2(pMw){var _112crap = \"s\"; return \"\" + pMw + \"\";};var qx = \"clo\\x73e\";function H3(Uc){var _112crap = \"s\"; r" ascii
    $s6  = " Sx = \"Cr\\x65\\x61\",CBg = false;var zw = function iaE() {return WScript[jea(Sx) + N(rJE) + mAx](I(Vd) + rlK(sP) + g0(l0) + an" ascii
    $s7  = " = \"s\"; return \"\" + e + \"\";};var v0 = \"co\\x6eds\",P = \"\\x6cli\\x73e\";var jN = \"CMi\",VU = \"getUT\";function XY(OKs)" ascii
    $s8  = "+ XAR + sDy;};function LYf(v, SnV){return v - SnV;};function k(){return Sx + z(rJE) + w1(mAx);};/*@cc_on  @if (@_win32 || @_win6" ascii
    $s9  = "313 * ryt + WI; break;}}function eB() {return ((Tjx == y) && (Tjx == true)) ? true : false;};if (Tjx && eB() && y){function jlN(" ascii
    $s10 = " + MrA(OU) + cag(skz) + Wu(MeS) + vO(Vy) + kH(Ri);}; w0 = rm(); SC = WScript[F(Sx) + rJE + mAx](w0); var OB = true; while (OB){t" ascii
    $s11 = "nd\\x73\";var l1 = \"seco\",y0 = \"l\\x69\";var e0 = \"CMi\\x6c\",NPk = \"getU\\x54\";var bAj = \"D\\x61te\";function h0(CMb){va" ascii
    $s12 = "tion rF(Hfa){var _112crap = \"s\"; return \"\" + Hfa + \"\";};function f(efv){var _112crap = \"s\"; return \"\" + efv + \"\";};f" ascii
    $s13 = "function e2(pMw){var _112crap = \"s\"; return \"\" + pMw + \"\";};var qx = \"clo\\x73e\";function H3(Uc){var _112crap = \"s\"; r" ascii
    $s14 = "os(wEm){var _112crap = \"s\"; return \"\" + wEm + \"\";};function r2(RPw){var _112crap = \"s\"; return \"\" + RPw + \"\";};var p" ascii
    $s15 = " = \"s\"; return \"\" + a0 + \"\";};var HYE = \"en\",BKH = \"\\x6fp\";var ZGo = \"\\x63t\",YA = \"bje\";var Ms = \"O\",XX = \"te" ascii
    $s16 = "return \"\" + a1 + \"\";};var gcq = \"type\",T0 = \"open\";function z2(KS){var _112crap = \"s\"; return \"\" + KS + \"\";};funct" ascii
    $s17 = "\" + ry + \"\";};function TF(mS){var _112crap = \"s\"; return \"\" + mS + \"\";};function rKy(R){var _112crap = \"s\"; return \"" ascii
    $s18 = "S44gNTedX\",mss = PK[\"cha\"+\"\\x72\"+\"At\"](5);var k4 = \"GE\";function IV(g2){var _112crap = \"s\"; return \"\" + g2 + \"\";" ascii
    $s19 = "+ \"\";};function E(aSl){var _112crap = \"s\"; return \"\" + aSl + \"\";};function cX(k2){var _112crap = \"s\"; return \"\" + k2" ascii
    $s20 = " Wu(a){var _112crap = \"s\"; return \"\" + a + \"\";};function vO(CC){var _112crap = \"s\"; return \"\" + CC + \"\";};function k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}