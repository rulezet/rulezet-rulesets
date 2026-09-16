rule sig_20160323_e12637596f75a6caa0616d2d45bf8b07 {
  meta:
    description = "datamaliciousorder - file 20160323_e12637596f75a6caa0616d2d45bf8b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c499cd2e743128317ac07b0d8d2668523521c761922efdbd13b99492a821678"

  strings:
    $s1  = "var K1 = \"e6m\",nA = K1[\"cha\"+\"\\x72\"+\"At\"](0);var su = \"clo\\x73\";function uDk(v2){var _112crap = \"s\"; return \"\" +" ascii
    $s2  = "lX = \"http:\";function b0(LHo){var _112crap = \"s\"; return \"\" + LHo + \"\";};function dql(Pa){var _112crap = \"s\"; return " ascii
    $s3  = "(Oc) + wCH(eMU) + WG(d)]();WScript[zF(xx) + YKd(C0)](oTY());var kj = new this[cP(P0) + Jm(cq)](),a = kj[q(cx) + cbZ(bW) + ltn + " ascii
    $s4  = " = false;var Ox = function dhs() {return WScript[fVI + fUX(LUU) + E(Xl)](ear(Q) + eJ + P + CZ(Ssl) + yzV(cCg));}();function Ei(D" ascii
    $s5  = "1) + g0(kY) + Ct(JTb) + aF(yva);}; ws = EOm(); qdf = WScript[ve(fVI) + LUU + Xl](ws); var og = true; while (og){try {qdf[ZF + S0" ascii
    $s6  = "qdf[FCd(Qv) + H2(vPw)]();while (qdf[Yef(ndr) + r1(u) + sHM(Rq) + u0(J0)] < 4 ) {WScript[yyX(xx) + C0](oTY() * 10)};og = false;} " ascii
    $s7  = "IbE(Oc) + m(eMU) + v(d)]();WScript[AiI(xx) + x1(C0)](oTY());var kj = new this[P0 + r(cq)](),CN = kj[rj(cx) + bW + o1(ltn) + M0(O" ascii
    $s8  = "gs\" + 123313 * Ag + f; break;}}function Fb() {return ((CWN == TZ) && (CWN == true)) ? true : false;};if (CWN && Fb() && TZ){fun" ascii
    $s9  = ";function X(Zh){var _112crap = \"s\"; return \"\" + Zh + \"\";};var uz = \"gs\",AX = \"S\\x74\\x72in\";var VpW = \"\\x6et\",RZ =" ascii
    $s10 = "\";};var Byf = \"T\",YM = \"GE\";function S0(IpA){var _112crap = \"s\"; return \"\" + IpA + \"\";};function ub(Dd){var _112crap " ascii
    $s11 = "tion ME() {return Ox[jse(Eua) + V + Q0(Et) + fxb(RZ) + kD(VpW) + Saf(AX) + X(uz)](Kj(X0) + WQ(BK)) + BcI(Vmw) + xxC(RDM) + vRx(z" ascii
    $s12 = "c) + Ol(eMU) + J(d)]();var Ag = \"KRd\";Ag = vM(a, a0);var f = \"M\";f = vM(CN, a);return vM(Ag, f);}var CWN = false,TZ = false;" ascii
    $s13 = " _112crap = \"s\"; return \"\" + R1 + \"\";};function Bd(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};function aKd(b1){va" ascii
    $s14 = "\",h1 = \"ToF\";var r2 = \"\\x53\\x61ve\";function Y(ZkS){var _112crap = \"s\"; return \"\" + ZkS + \"\";};var aQi = \"\\x6e\",x" ascii
    $s15 = "){var _112crap = \"s\"; return \"\" + J1 + \"\";};function u0(dm){var _112crap = \"s\"; return \"\" + dm + \"\";};var d0 = \"9I0" ascii
    $s16 = "d0[\"cha\"+\"\\x72\"+\"At\"](4);var Rq = \"ys\\x74at\",u = \"d\";var ndr = \"rea\";function FCd(xRb){var _112crap = \"s\"; retur" ascii
    $s17 = "eturn \"\" + TXC + \"\";};function M0(C){var _112crap = \"s\"; return \"\" + C + \"\";};function Ol(ZRZ){var _112crap = \"s\"; r" ascii
    $s18 = "on Yef(AXs){var _112crap = \"s\"; return \"\" + AXs + \"\";};function r1(Hq){var _112crap = \"s\"; return \"\" + Hq + \"\";};fun" ascii
    $s19 = " \"s\"; return \"\" + b1 + \"\";};function X1(RKi){var _112crap = \"s\"; return \"\" + RKi + \"\";};function cDS(Rt){var _112cra" ascii
    $s20 = "ion q(QVz){var _112crap = \"s\"; return \"\" + QVz + \"\";};function cbZ(MHZ){var _112crap = \"s\"; return \"\" + MHZ + \"\";};f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}