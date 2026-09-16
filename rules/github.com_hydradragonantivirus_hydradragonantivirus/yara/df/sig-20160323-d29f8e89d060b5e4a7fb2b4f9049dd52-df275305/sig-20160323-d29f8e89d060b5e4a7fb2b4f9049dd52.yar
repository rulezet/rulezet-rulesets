rule sig_20160323_d29f8e89d060b5e4a7fb2b4f9049dd52 {
  meta:
    description = "datamaliciousorder - file 20160323_d29f8e89d060b5e4a7fb2b4f9049dd52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66158448e500e6aea3f5c78535dde98f91a4a8a0e56d6be190b8acd93aacd2f9"

  strings:
    $s1  = ") + nv(Xwr) + nPO(Xry)]();WScript[n0(a) + ld](M());var DD = new this[RS(bB)](),Lr = DD[U + k2(Lb) + i(XBK) + tSH(C) + AQ(Hk) + J" ascii
    $s2  = "p(Xwr) + P(Xry)]();WScript[nO(a) + QpO(ld)](M());var DD = new this[t(bB)](),k0 = DD[nAm(U) + gQG(Lb) + ZR(XBK) + I1(C) + Hk + Y0" ascii
    $s3  = " = false,G = function AL() {return WScript[u0(mB) + RBn(G0) + Svk(n) + e(MQk)](yc(PXX) + r + cv(vr) + Wms + Nnk);}();function HM" ascii
    $s4  = "(rA){G[I + Dt](rA, 0, 0);};function k(){return f(R) + Os(gH) + ToL(CWQ) + J(Mir) + erA(rF);};function z(Rr, Sr){return Rr - Sr;}" ascii
    $s5  = "13 * Q0 + Q; break;}}function AbM() {return ((D == Oby) && (D == true)) ? true : false;};if (D && AbM() && Oby){function Nyi() {" ascii
    $s6  = "function JW(lEQ){var _112crap = \"s\"; return \"\" + lEQ + \"\";};function YA(tQS){var _112crap = \"s\"; return \"\" + tQS + \"" ascii
    $s7  = "(zHk) + YZ(p2)]();while (Y[mKj(ok) + v0 + gL] < 4 ) {WScript[a + Qy(ld)](M() * 10)};yud = false;} catch(OIT){yud = (Aeo + di + q" ascii
    $s8  = "ap = \"s\"; return \"\" + WCG + \"\";};function Svk(uq){var _112crap = \"s\"; return \"\" + uq + \"\";};function e(g){var _112cr" ascii
    $s9  = "q){var _112crap = \"s\"; return \"\" + qq + \"\";};function ly(U0){var _112crap = \"s\"; return \"\" + U0 + \"\";};var Xry = \"d" ascii
    $s10 = "= \"w\\x72\";var sUi = \"\\x65\",j = \"typ\";var XT = \"en\",K2 = \"\\x70\";var Xpm = \"\\x6f\";function PGG(B){var _112crap = " ascii
    $s11 = "rue; while (yud){try {Y[f0(O0)](zW(l), p1(Nv) + yVq(DYf) + Om(uw) + J1(ZU) + SS + k3 + eg(nz) + S(Rg) + AdW(L) + D2, false);Y[VI" ascii
    $s12 = "\"\";};function RS(vh){var _112crap = \"s\"; return \"\" + vh + \"\";};function t(d){var _112crap = \"s\"; return \"\" + d + \"" ascii
    $s13 = "nction J(J0){var _112crap = \"s\"; return \"\" + J0 + \"\";};function erA(kn){var _112crap = \"s\"; return \"\" + kn + \"\";};va" ascii
    $s14 = "s\"; return \"\" + KoB + \"\";};function tSH(w){var _112crap = \"s\"; return \"\" + w + \"\";};function AQ(xp){var _112crap = \"" ascii
    $s15 = " + \"\";};function yVq(Dj){var _112crap = \"s\"; return \"\" + Dj + \"\";};function Om(Eft){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = "B + \"\";};function tQk(Sb){var _112crap = \"s\"; return \"\" + Sb + \"\";};var wZ = \"re\\x61m\",E1 = \"t\";var r0 = \".S\",spL" ascii
    $s17 = "0 + P4, d1 + BES(Six), LxC + Q3(dgP), true);};}function gCn(Bn) {var FN = (1, 2, 3, 4, 5, Bn); return FN;};Q0 = (D) ? 14134 : 41" ascii
    $s18 = "nction ru(syA){var _112crap = \"s\"; return \"\" + syA + \"\";};function Zqm(KD){var _112crap = \"s\"; return \"\" + KD + \"\";}" ascii
    $s19 = "return G[q + c0(BM) + HAU(tR) + iK0 + D1(Wg) + O(D0) + wPi(P2) + WsI(Q1)](cGA(PuT) + Z(kYf) + Y1(hb) + cDZ(wwt) + auP(CO)) + NI " ascii
    $s20 = "_112crap = \"s\"; return \"\" + iK + \"\";};function k2(co){var _112crap = \"s\"; return \"\" + co + \"\";};function i(KoB){var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}