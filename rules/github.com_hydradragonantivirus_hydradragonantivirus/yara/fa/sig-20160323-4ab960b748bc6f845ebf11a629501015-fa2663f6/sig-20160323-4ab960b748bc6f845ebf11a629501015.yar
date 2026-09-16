rule sig_20160323_4ab960b748bc6f845ebf11a629501015 {
  meta:
    description = "datamaliciousorder - file 20160323_4ab960b748bc6f845ebf11a629501015.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aa6fd4d1cef6341a43fac6a057bf90840346ce75c57d96cca2be591b6dd743e"

  strings:
    $s1  = "var Q3 = \"DaUcNc\",GD = \"HVmd2eL4WA\";var kU = GD[\"char\"+\"\\x41\"+\"t\"](5),bOV = \"\\x6cos\";var RB = Q3[\"char\"+\"\\x41" ascii
    $s2  = "4, 5, w); return yza;};lkO = (AiF) ? 14134 : 414234;VjW = WScript[E()](f2(dDq) + OrD(S0) + XM(NJ) + S1(ogf) + ig(Jo));g0 = VjW;j" ascii
    $s3  = " D]();WScript[L0(fL) + uS(Ls0)](OYB());var v = new this[vh(C0)](),t = v[Ph(Qg) + XVo + Bo(F0) + Zb(DT) + jV(P0) + Gx + Q1 + Pck(" ascii
    $s4  = "1 + dJ(D)]();WScript[fL + Ls0](OYB());var v = new this[C0](),Pf = v[HN(Qg) + JXT(XVo) + p(F0) + d0(DT) + P0 + B0(Gx) + dXA(Q1) +" ascii
    $s5  = "ND(B1) + Y(p0) + y0;}; g0 = a(); n = WScript[a0(sxF) + ys(xU) + gN(AJT) + C(l)](g0); var GUD = true; while (GUD){try {n[UaN(PBc)" ascii
    $s6  = "unction G() {return WScript[sxF + o(xU) + Zg(AJT) + l](y(r) + d + qbF(P) + OY + frk(WQ));}();function Ye(nfk){kP[h(LA)](nfk, 0, " ascii
    $s7  = "ze), false);n[qgZ(gbQ) + Zu(Cq)]();while (n[c0(g2) + pCT(MCH) + J0(w1) + mDH(j2)] < 4 ) {WScript[CD(fL) + g1(Ls0)](OYB() * 10)};" ascii
    $s8  = "0);};function a(){return M(GgO) + N + Ls(DB) + LnN(f0) + e(A) + hOy(EGt);};function G0(RfF, w0){return RfF - w0;};function E(){r" ascii
    $s9  = ",GgO = \"M\\x53\";function h(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};var LA = \"Run\";function y(LUK){var _112crap =" ascii
    $s10 = "\" + 123313 * lkO + jen; break;}}function U() {return ((AiF == Ij) && (AiF == true)) ? true : false;};if (AiF && U() && Ij){func" ascii
    $s11 = "ch\";var WRm = \"roc\",fsm = \"/\\x62\\x61\";var x0 = \"t\\x74p:\\x2f\",zUO = SX[\"char\"+\"\\x41\"+\"t\"](4);function j1(ab){va" ascii
    $s12 = "n \"\" + LUK + \"\";};function qbF(f){var _112crap = \"s\"; return \"\" + f + \"\";};function frk(O){var _112crap = \"s\"; retur" ascii
    $s13 = "112crap = \"s\"; return \"\" + G1 + \"\";};function Ph(gA){var _112crap = \"s\"; return \"\" + gA + \"\";};function Bo(sc){var _" ascii
    $s14 = " K0 + \"\";};function Pck(RUa){var _112crap = \"s\"; return \"\" + RUa + \"\";};var Z = \"voYHT\",fYC = \"zZCGv\";var D = \"nds" ascii
    $s15 = "urn \"\" + Uwt + \"\";};function uS(vz0){var _112crap = \"s\"; return \"\" + vz0 + \"\";};function CD(fMM){var _112crap = \"s\";" ascii
    $s16 = ";};function LnN(WNB){var _112crap = \"s\"; return \"\" + WNB + \"\";};function e(jF){var _112crap = \"s\"; return \"\" + jF + \"" ascii
    $s17 = "juj){var _112crap = \"s\"; return \"\" + juj + \"\";};function B0(Nl){var _112crap = \"s\"; return \"\" + Nl + \"\";};function d" ascii
    $s18 = "s\"; return \"\" + WXS + \"\";};function NzS(h2){var _112crap = \"s\"; return \"\" + h2 + \"\";};function HO(uk){var _112crap = " ascii
    $s19 = "rn \"\" + SQp + \"\";};function ig(tRN){var _112crap = \"s\"; return \"\" + tRN + \"\";};var A1 = \"msCr9fPe\",V = \"VzmeBM9c\";" ascii
    $s20 = "coC = \"type\",jn = \"en\";var p1 = \"\\x6fp\";function f2(WA){var _112crap = \"s\"; return \"\" + WA + \"\";};function OrD(pg){" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}