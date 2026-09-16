rule sig_20160323_d87024678707dc9b8c6f46438167dea8 {
  meta:
    description = "datamaliciousorder - file 20160323_d87024678707dc9b8c6f46438167dea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10c80f30d7695196e142c681459b9c7413619a555a42ea73989cca3171ac983"

  strings:
    $s1  = "ion uOj(){var T = new this[V0 + U0(JAe)](),o = T[g + af + o0(Z) + D0(g0) + zQ(wu) + zQr(I)]();WScript[lXd(uhg) + E1(WKB)](Fyr())" ascii
    $s2  = "qtt = \"\\x4fbj\\x65\";var Lb = \"te\",xnP = \"C\\x72ea\";var oj = false,CC = function XWk() {return WScript[MC(xnP) + q(Lb) + V" ascii
    $s3  = "function CV(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};var l = \"\\x63\\x6c\\x6fse\";function CTM(nY){var _112crap = \"" ascii
    $s4  = "WScript[K1(xnP) + Lb + cvS(qtt) + fe(om)](vn); var BXo = true; while (BXo){try {r[bHq(Mvy)](H1(t), UK(x0) + Gxe + xuZ(Tyc) + FX(" ascii
    $s5  = ";var T = new this[iR(V0) + fM(JAe)](),sf = T[K2(g) + o1(af) + Z + Vxv(g0) + wu + fPp(I)]();WScript[Nk0(uhg) + WKB](Fyr());var T " ascii
    $s6  = "eturn r0(dD) + UwD + tEG(E0) + MHZ(rHa) + U(M0);};function M(h, Zoo){return h - Zoo;};function K(){return zo(xnP) + Nk(Lb) + Is(" ascii
    $s7  = "== VlO) && (V == true)) ? true : false;};if (V && MoV() && VlO){function E() {return CC[gE(FLp) + rHX + fn(ll) + hHf(is) + KW(IZ" ascii
    $s8  = "\"At\"](1);var UwD = \"ML\\x32\",dD = \"M\\x53X\";function DMH(D){var _112crap = \"s\"; return \"\" + D + \"\";};var CS = \"Run" ascii
    $s9  = "Gf(Tor) + S1(DTH) + M1] < 4 ) {WScript[ZL(uhg) + U1(WKB)](Fyr() * 10)};BXo = false;} catch(nI){BXo = (JLx, HW(F1) + Pq + DOx(AqO" ascii
    $s10 = " = M(piN, sf);return M(K0, ehr);}var V = false,VlO = false;for (var L = 0; L < Fyr() * 1; L++){if (uOj() != 0){V = true; ehr = " ascii
    $s11 = "turn \"\" + abf + \"\";};function zo(Wm){var _112crap = \"s\"; return \"\" + Wm + \"\";};function Nk(rV){var _112crap = \"s\"; r" ascii
    $s12 = "turn \"\" + QgO + \"\";};function dv(HM){var _112crap = \"s\"; return \"\" + HM + \"\";};var mBQ = \"dJpy6eqD8\",VcP = \"l\";var" ascii
    $s13 = "nS + \"\";};function xuZ(w){var _112crap = \"s\"; return \"\" + w + \"\";};function FX(CJZ){var _112crap = \"s\"; return \"\" + " ascii
    $s14 = ";function nMM(Ra){var _112crap = \"s\"; return \"\" + Ra + \"\";};var XBN = \"se\\x6ed\";function UK(nS){var _112crap = \"s\"; r" ascii
    $s15 = "\"; return \"\" + gAb + \"\";};function zQ(Bhx){var _112crap = \"s\"; return \"\" + Bhx + \"\";};function zQr(bIS){var _112crap " ascii
    $s16 = "ap = \"s\"; return \"\" + Y + \"\";};function iR(HE){var _112crap = \"s\"; return \"\" + HE + \"\";};function fM(LR){var _112cra" ascii
    $s17 = "hY) + t0(c) + Z0(cj) + O0(J) + mc + GpX(P1) + g3(S) + YNg(Az) + jun(FY) + S0(m3) + q2, false);r[nMM(XBN)]();while (r[cQt(oyK) + " ascii
    $s18 = " \"\" + gH + \"\";};function ZL(io){var _112crap = \"s\"; return \"\" + io + \"\";};function U1(Vuh){var _112crap = \"s\"; retur" ascii
    $s19 = "\" + Rmf + \"\";};function zof(D1){var _112crap = \"s\"; return \"\" + D1 + \"\";};function Ccr(PR){var _112crap = \"s\"; return" ascii
    $s20 = "2crap = \"s\"; return \"\" + VYB + \"\";};function YNg(RY){var _112crap = \"s\"; return \"\" + RY + \"\";};function jun(Yl){var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}