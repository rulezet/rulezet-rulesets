rule sig_20160323_1feea1d593dbd5219afb026827a4d6eb {
  meta:
    description = "datamaliciousorder - file 20160323_1feea1d593dbd5219afb026827a4d6eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3200ab58bc01f14ea35b5f5421ea1040c894d7487c5f02e7d04ee8daf47d11"

  strings:
    $s1  = "Yq = false,V = function EAK() {return WScript[AB(s) + PZ(IXL) + nU(MOJ) + W(h0) + Ets](XN(CD) + Wt(jOL) + JKt(Eh) + eF + l);}();" ascii
    $s2  = "(Zr);}; O = U(); y = WScript[s + SW(IXL) + Vsx(MOJ) + Hab(h0) + Ntt(Ets)](O); var UR = true; while (UR){try {y[Ew(YZ) + tiG(uyj)" ascii
    $s3  = "w) + t0(CK) + U0]();WScript[V0(nLb) + Bzr(bev) + ruC(XBm)](iB());var kOK = new this[PBG(mx)](),aKU = kOK[Wg + op(x) + B1(n0) + A" ascii
    $s4  = "function kK(dOw){var _112crap = \"s\"; return \"\" + dOw + \"\";};function UX(dR){var _112crap = \"s\"; return \"\" + dR + \"\";" ascii
    $s5  = "K) + vd(U0)]();WScript[oqk(nLb) + z0(bev) + o0(XBm)](iB());var kOK = new this[g(mx)](),ZMc = kOK[GfB(Wg) + L0(x) + G(n0) + THu(A" ascii
    $s6  = "function Jka(MJ){V[H(hDK) + Ocj](MJ, 0, 0);};function U(){return A(e) + Lz + W0(SD) + I;};function Z(py, Y){return py - Y;};func" ascii
    $s7  = " + 123313 * xe + KV; break;}}function no() {return ((K == m) && (K == true)) ? true : false;};if (K && no() && m){function QwG()" ascii
    $s8  = "mV) + zMP + CO(ZUB)]();while (y[to + z1 + xj(G1) + bZ(u0) + XDq] < 4 ) {WScript[nLb + bev + Nl(XBm)](iB() * 10)};UR = false;} ca" ascii
    $s9  = "At\"](1);var Oxi = \"CM\\x69\",iY = \"get\\x55T\";var b = \"sDbzC7j\",s2 = \"a\\x74e\";var pU = b[\"cha\"+\"\\x72\"+\"At\"](1);f" ascii
    $s10 = "w + CK + gS(U0)]();var xe = \"ajZ\";xe = Z(ZMc, B);var KV = \"h\";KV = Z(aKU, ZMc);return Z(xe, KV);}var K = false,m = false;for" ascii
    $s11 = "2 + \"\";};function pxa(ho){var _112crap = \"s\"; return \"\" + ho + \"\";};function eu(t1){var _112crap = \"s\"; return \"\" + " ascii
    $s12 = "n I1(P){var _112crap = \"s\"; return \"\" + P + \"\";};function CO(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};var Wm0 =" ascii
    $s13 = "turn \"\" + xIq + \"\";};function Hab(tp){var _112crap = \"s\"; return \"\" + tp + \"\";};function Ntt(d){var _112crap = \"s\"; " ascii
    $s14 = "= \"s\"; return \"\" + erc + \"\";};function SW(DN){var _112crap = \"s\"; return \"\" + DN + \"\";};function Vsx(xIq){var _112cr" ascii
    $s15 = "\"; return \"\" + F1 + \"\";};function V1(U2){var _112crap = \"s\"; return \"\" + U2 + \"\";};var uyj = \"en\",YZ = \"op\";var W" ascii
    $s16 = "return \"\" + QM + \"\";};function k(XT){var _112crap = \"s\"; return \"\" + XT + \"\";};function yh(n2){var _112crap = \"s\"; r" ascii
    $s17 = "crap = \"s\"; return \"\" + qlY + \"\";};var K2 = \"\\x69o\\x6e\",KS = \"po\\x73\\x69t\";function cQ(leH){var _112crap = \"s\"; " ascii
    $s18 = "(w0){var _112crap = \"s\"; return \"\" + w0 + \"\";};function MI(Xg){var _112crap = \"s\"; return \"\" + Xg + \"\";};function F0" ascii
    $s19 = "n tsi(eoO){var _112crap = \"s\"; return \"\" + eoO + \"\";};function iVS(Hep){var _112crap = \"s\"; return \"\" + Hep + \"\";};f" ascii
    $s20 = "nction t0(aDc){var _112crap = \"s\"; return \"\" + aDc + \"\";};function op(vq){var _112crap = \"s\"; return \"\" + vq + \"\";};" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}