rule sig_20160323_86ba4b44ce6baa1b64cf01d375600001 {
  meta:
    description = "datamaliciousorder - file 20160323_86ba4b44ce6baa1b64cf01d375600001.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5228fa18208bbd9a2fc17bc2c5fcee1b58a1d91dd15a5a1ac8a3c702d32cac"

  strings:
    $s1  = "function tYV(iI){var _112crap = \"s\"; return \"\" + iI + \"\";};function ca(Xpp){var _112crap = \"s\"; return \"\" + Xpp + \"\"" ascii
    $s2  = "* xGx + Vd; kME = true; Vd = \"07t9gasdf76ags\" + 123313 * xGx + Vd; break;}}function q() {return ((d == kME) && (d == true)) ? " ascii
    $s3  = "\\x72\"+\"At\"](0);var XJ = \"\\x65ateO\",K = \"\\x43\\x72\";var yxy = false,rm = function zDW() {return WScript[wZP(K) + y(XJ) " ascii
    $s4  = "new this[XHv + vKa(Wr)](),f = Zkn[ieQ(Qz) + h(oB) + EmK(wxF) + Vl(B)]();WScript[UE(V0) + afs(r1)](piH());var Zkn = new this[n(XH" ascii
    $s5  = "unction BBh(){var Zkn = new this[mj(XHv) + p0(Wr)](),Y = Zkn[Qz + CM(oB) + wxF + w0(B)]();WScript[V0 + IX(r1)](piH());var Zkn = " ascii
    $s6  = "iYi, true);};}function RB(Ly) {var k0 = (1, 2, 3, 4, 5, Ly); return k0;};xGx = (d) ? 14134 : 414234;SUe = WScript[V()](H(C2) + K" ascii
    $s7  = " = \"getUT\";function mj(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function p0(qpM){var _112crap = \"s\"; return \"\" " ascii
    $s8  = "\"\\x2f\\x2f\";var Q = \"\\x70:\",pF = \"\\x68t\\x74\";function F(Uxm){var _112crap = \"s\"; return \"\" + Uxm + \"\";};var rI =" ascii
    $s9  = " TNa + t(ESV) + cB(j0) + S(rW) + Ul;};function k(WXc, Cih){return WXc - Cih;};function V(){return zf(K) + HlF(XJ) + gf(MSG) + x(" ascii
    $s10 = "ue : false;};if (d && q() && kME){function RmC() {return rm[mx(jsM) + o0(T0) + Fla(W2) + t2(ymO) + jx(CQ) + t3(fL) + sWs(QZl) + " ascii
    $s11 = "\\x6cee\";function n0(Bjf){var _112crap = \"s\"; return \"\" + Bjf + \"\";};function v0(qO){var _112crap = \"s\"; return \"\" + " ascii
    $s12 = "fV(MSG) + a + X(uRR)](ld); var dvX = true; while (dvX){try {Sc[l0(b0) + KN(yW)](F(rI), pF + uiY(Q) + Vb(t4) + kx(eEu) + LP(aIq) " ascii
    $s13 = "3\"+\"ha\"+\"\\x72\"+\"At\"](3);function uWk(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};var c = \"cDtPLng0\",I0 = c[\"" ascii
    $s14 = "0(eA){var _112crap = \"s\"; return \"\" + eA + \"\";};function ieQ(gGO){var _112crap = \"s\"; return \"\" + gGO + \"\";};functio" ascii
    $s15 = "0(ID){var _112crap = \"s\"; return \"\" + ID + \"\";};function KN(cjj){var _112crap = \"s\"; return \"\" + cjj + \"\";};function" ascii
    $s16 = "61fa\",jSG = \"afd\";function S0(a1){var _112crap = \"s\"; return \"\" + a1 + \"\";};function O(vcQ){var _112crap = \"s\"; retur" ascii
    $s17 = "r _112crap = \"s\"; return \"\" + diq + \"\";};function E(dv){var _112crap = \"s\"; return \"\" + dv + \"\";};var T1 = \"oIj\",y" ascii
    $s18 = ";function wZP(e){var _112crap = \"s\"; return \"\" + e + \"\";};function y(prZ){var _112crap = \"s\"; return \"\" + prZ + \"\";}" ascii
    $s19 = "v) + FT(Wr)](),C = Zkn[N0(Qz) + m0(oB) + CxH(wxF) + B]();var xGx = \"r\";xGx = k(f, Y);var Vd = \"qb\";Vd = k(C, f);return k(xGx" ascii
    $s20 = "p = \"s\"; return \"\" + PVF + \"\";};function cSA(I){var _112crap = \"s\"; return \"\" + I + \"\";};function RJ(N4){var _112cra" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}