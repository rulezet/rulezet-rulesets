rule sig_20160323_619142a42d2a6c3fa0eec13437b89185 {
  meta:
    description = "datamaliciousorder - file 20160323_619142a42d2a6c3fa0eec13437b89185.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "314c8c4b44451991833d8811c1bb2bbfc7e283bca03e523093768081a463e8ac"

  strings:
    $s1  = "function J1(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};var X4 = \"\\x63lose\";function Me(aKt){var _112crap = \"s\"; retu" ascii
    $s2  = " + O0(G);}; R = gIe(); DU = WScript[XaF + wMK(y) + XM(IV)](R); var Kt = true; while (Kt){try {DU[VO(JsW) + rC(G0) + ZX](HIw + xc" ascii
    $s3  = "\"\\x6aect\",y = \"t\\x65O\\x62\";var XaF = \"Crea\",W0 = false;var Ga = function K() {return WScript[vk(XaF) + y + OZ(IV)](VR(V" ascii
    $s4  = "false);DU[c1(UA) + X1(nZ) + FHo(aq)]();while (DU[TIR(Sl) + m4 + Gk(qQt) + WII + ce(Xwn) + m5(EN)] < 4 ) {WScript[nNR(MGM) + fKv(" ascii
    $s5  = " 2, 3, 4, 5, x); return CY;};zeq = (mh) ? 14134 : 414234;qw = WScript[OC()](MO(wL) + n1 + SJe + CL0(Pp));R = qw;Ij = (eV) ? zeq " ascii
    $s6  = "this[P0 + u0(NFv) + Li(bdt)](),i = c[xoQ(CkU) + p(i0) + EUP + R0(t) + Dj(S0) + Kvt + U0(P1) + FI(n)]();WScript[cuw(MGM) + zW(dLG" ascii
    $s7  = "(x1);};function Sa(xri, Ydg){return xri - Ydg;};function OC(){return VDL(XaF) + OHh(y) + K0(IV);};/*@cc_on  @if (@_win32 || @_wi" ascii
    $s8  = "+ 123313 * zeq + Ij; break;}}function W() {return ((mh == eV) && (mh == true)) ? true : false;};if (mh && W() && eV){function PL" ascii
    $s9  = "function c3(e1){var _112crap = \"s\"; return \"\" + e1 + \"\";};function F2(Cox){var _112crap = \"s\"; return \"\" + Cox + \"\";" ascii
    $s10 = "\\x69\";function cF(Zq){var _112crap = \"s\"; return \"\" + Zq + \"\";};function lDE(tA){var _112crap = \"s\"; return \"\" + tA " ascii
    $s11 = "e\\x64\",Kvt = \"co\";var S0 = \"\\x6cise\",t = \"\\x69l\";var EUP = \"\\x4d\",i0 = \"T\\x43\";var CkU = \"getU\";function v(GZ)" ascii
    $s12 = "; return \"\" + Kyq + \"\";};function Xm(AU){var _112crap = \"s\"; return \"\" + AU + \"\";};function N(AHX){var _112crap = \"s" ascii
    $s13 = "rA\"+\"\\x74\"+\"\"](5);var LOM = \"t\\x65\",ws = \"\\x44a\";function c0(zmF){var _112crap = \"s\"; return \"\" + zmF + \"\";};f" ascii
    $s14 = "\"; return \"\" + r1 + \"\";};function Ks(x2){var _112crap = \"s\"; return \"\" + x2 + \"\";};var ois = \"lAM\",hV = \"J.\";var " ascii
    $s15 = "\"s\"; return \"\" + r + \"\";};function OZ(au){var _112crap = \"s\"; return \"\" + au + \"\";};function VDL(Q){var _112crap = " ascii
    $s16 = "p = \"s\"; return \"\" + Wor + \"\";};var k1 = \"s\",T1 = \"t\\x72i\\x6eg\";var J = \"ntS\",IyJ = \"ronm\\x65\";var Y2 = \"d\\x4" ascii
    $s17 = "A + \"\";};function htb(cU){var _112crap = \"s\"; return \"\" + cU + \"\";};function yzc(St){var _112crap = \"s\"; return \"\" +" ascii
    $s18 = "rap = \"s\"; return \"\" + pB + \"\";};function U(roD){var _112crap = \"s\"; return \"\" + roD + \"\";};function b(w){var _112cr" ascii
    $s19 = "rap = \"s\"; return \"\" + nvI + \"\";};function rx(LWV){var _112crap = \"s\"; return \"\" + LWV + \"\";};function F(CT){var _11" ascii
    $s20 = "\"; return \"\" + GZ + \"\";};function u0(T){var _112crap = \"s\"; return \"\" + T + \"\";};function Li(A){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}