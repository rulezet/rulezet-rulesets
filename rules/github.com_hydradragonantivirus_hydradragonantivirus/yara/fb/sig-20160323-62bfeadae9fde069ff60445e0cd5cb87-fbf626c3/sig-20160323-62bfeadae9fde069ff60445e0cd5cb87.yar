rule sig_20160323_62bfeadae9fde069ff60445e0cd5cb87 {
  meta:
    description = "datamaliciousorder - file 20160323_62bfeadae9fde069ff60445e0cd5cb87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70f7259b9c7b55c951057d821d6dbfb21d08ed51024e9be1456fb4439a0d047"

  strings:
    $s1  = " 2, 3, 4, 5, C); return fg;};TsX = (c) ? 14134 : 414234;pyh = WScript[DU()](VO(rf) + DDJ(L2) + p0(kE));b = pyh;YfP = (B) ? TsX :" ascii
    $s2  = "y)) + nV(a3) + Pe(lh) + x0(xDj) + Vf(VeL);}; b = Lf(); g = WScript[wQo(HF) + uT(KlV) + Xxb(CU) + h(YIk) + P](b); var d = true; w" ascii
    $s3  = ",C0 = function y() {return WScript[ZFl(HF) + TLu(KlV) + s(CU) + DyM(YIk) + P](K(ZBu) + Ab(r) + h0 + EdT(XP));}();function a(iNQ)" ascii
    $s4  = " + AQl(JQr) + a1(fD) + eW]();WScript[v0(noV) + Xs(y0)](Y());var k = new this[N0 + ONH(qD)](),zix = k[Gc(Y0) + lC(UUr) + tB + WzY" ascii
    $s5  = "(t0) + JQr + x(fD) + c0(eW)]();WScript[q(noV) + rIt(y0)](Y());var k = new this[w0(N0) + t(qD)](),CHv = k[rQX(Y0) + mP(UUr) + Kue" ascii
    $s6  = "function OGb(o){var _112crap = \"s\"; return \"\" + o + \"\";};function Pa(XK){var _112crap = \"s\"; return \"\" + XK + \"\";};v" ascii
    $s7  = "{C0[YvJ(PV)](iNQ, 0, 0);};function Lf(){return sB(cXO) + K0(fE) + LBR + J(KH) + IxU(Py) + l + IK;};function kB(N, qR){return N -" ascii
    $s8  = " (c && TNn() && B){function V() {return C0[n1(k0) + rlH(tZ) + ZA(BhE) + K3(hT) + Jn(AE) + YgO(mt) + Cdg(k1) + er](Veh(R) + Lf0(n" ascii
    $s9  = " true; YfP = \"07t9gasdf76ags\" + 123313 * TsX + YfP; break;}}function TNn() {return ((c == B) && (c == true)) ? true : false;};" ascii
    $s10 = "v\\x61cua\";var RSk = \"\\x2f\\x65\",GF = \":\\x2f\";var VOW = \"http\";function ZT(eYu){var _112crap = \"s\"; return \"\" + eYu" ascii
    $s11 = " + RQ, false);g[dp + Ca(eij)]();while (g[Uz(T) + Sy(j) + GP(pB) + C3 + isa(iN)] < 4 ) {WScript[cwU(noV) + SRK(y0)](Y() * 10)};d " ascii
    $s12 = "\\x54E\\x4dP\";function n1(NRG){var _112crap = \"s\"; return \"\" + NRG + \"\";};function rlH(wSk){var _112crap = \"s\"; return " ascii
    $s13 = "\\x72i\\x74e\";var QD = Qph[\"charA\"+\"\\x74\"+\"\"](1);function F0(aJ){var _112crap = \"s\"; return \"\" + aJ + \"\";};var tti" ascii
    $s14 = "; return \"\" + QQ0 + \"\";};function p0(SC){var _112crap = \"s\"; return \"\" + SC + \"\";};var kE = \"tr\\x65a\\x6d\",L2 = \"" ascii
    $s15 = "WzY(Ck){var _112crap = \"s\"; return \"\" + Ck + \"\";};function x(g0){var _112crap = \"s\"; return \"\" + g0 + \"\";};function " ascii
    $s16 = "\"\";};function Gc(v){var _112crap = \"s\"; return \"\" + v + \"\";};function lC(K1){var _112crap = \"s\"; return \"\" + K1 + \"" ascii
    $s17 = "\" + QQ + \"\";};function AQl(E0){var _112crap = \"s\"; return \"\" + E0 + \"\";};function a1(kTv){var _112crap = \"s\"; return " ascii
    $s18 = " \"\" + lsz + \"\";};function xO(L){var _112crap = \"s\"; return \"\" + L + \"\";};var VL = \"i9TlZ\",h1 = \"AoWsdo\";var eW = " ascii
    $s19 = "[\"charA\"+\"\\x74\"+\"\"](4);var dp = \"\\x73e\\x6e\";function Trv(xB){var _112crap = \"s\"; return \"\" + xB + \"\";};function" ascii
    $s20 = "\"s\"; return \"\" + XfX + \"\";};function rnY(yDK){var _112crap = \"s\"; return \"\" + yDK + \"\";};var ZyF = \"f\",E2 = \"asd" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}