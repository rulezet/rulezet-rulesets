rule sig_20160323_402f6408bd8ebfe46bcee4060fbf800f {
  meta:
    description = "datamaliciousorder - file 20160323_402f6408bd8ebfe46bcee4060fbf800f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6c8eb6c362375650971c36fb6d06daaa419f3a0a1d3ed2dfd19f69397225b3a"

  strings:
    $s1  = "MM(M0) + Ua(xQ) + KT(h) + Z0(Ge) + dvl(JgP)]();WScript[t(O) + p(dCn)](JH());var eKn = new this[Od + s0](),xb = eKn[rj(vf) + JA(R" ascii
    $s2  = " + QE(T0)) + Ir + pWD(IVU) + lbK(j) + pj(V2);}; e = FNH(); E = WScript[YG(RO) + e0 + X(tS) + P(dh)](e); var M = true; while (M){" ascii
    $s3  = "V0 = function b() {return WScript[B(RO) + e0 + SH(tS) + Vn(dh)](bQK(S) + s + FLh(UM) + T);}();function DoL(FX){V0[Bp(x) + Hr(Y0)" ascii
    $s4  = "h) + Z(Ge) + ZCh(JgP)]();WScript[KZp(O) + jas(dCn)](JH());var eKn = new this[RE(Od) + Qkv(s0)](),xZt = eKn[oYb(vf) + wST(RF) + O" ascii
    $s5  = "](FX, 0, 0);};function FNH(){return A0(ke) + w(c0) + ay(Gxo) + Q + dXl(P1) + ZwT(uWQ);};function EP(xr, RTo){return xr - RTo;};f" ascii
    $s6  = "() && Mt){function Vf() {return V0[Fd(SjB) + U(z1) + rTl(Vi) + i(OKH) + xHv(gO) + goK(WxA) + Hrr(mt) + BJf(Aqu) + d1(bFo)](B0(v)" ascii
    $s7  = "e; A = \"07t9gasdf76ags\" + 123313 * bk + A; break;}}function Bw() {return ((c == Mt) && (c == true)) ? true : false;};if (c && " ascii
    $s8  = "e);E[qn(j0)]();while (E[d2(tpL) + e1 + cIz(KtQ) + GS(B1)] < 4 ) {WScript[oP(O) + k2(dCn)](JH() * 10)};M = false;} catch(Iy){M = " ascii
    $s9  = "function H1(CN){var _112crap = \"s\"; return \"\" + CN + \"\";};var eP = \"kleQemr8e\",Gy = eP[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"" ascii
    $s10 = "12crap = \"s\"; return \"\" + bZW + \"\";};function dXl(o){var _112crap = \"s\"; return \"\" + o + \"\";};function ZwT(lQv){var " ascii
    $s11 = "W(O1){var _112crap = \"s\"; return \"\" + O1 + \"\";};function wqe(JyA){var _112crap = \"s\"; return \"\" + JyA + \"\";};var q1 " ascii
    $s12 = "Ip5Yt\",dCn = QK[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](1);var O = \"S\\x6ce\\x65\";function H(w0){var _112crap =" ascii
    $s13 = " \"eep\";var ajv = SV[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](1),ioK = \"S\";function d2(t1){var _112crap = \"s\";" ascii
    $s14 = "r _112crap = \"s\"; return \"\" + cL + \"\";};function ZCh(eOW){var _112crap = \"s\"; return \"\" + eOW + \"\";};function oYb(zo" ascii
    $s15 = "p = \"s\"; return \"\" + VzB + \"\";};function la(wRt){var _112crap = \"s\"; return \"\" + wRt + \"\";};var e2 = \"am\",gYr = \"" ascii
    $s16 = "12crap = \"s\"; return \"\" + vyT + \"\";};function pz(Qdw){var _112crap = \"s\"; return \"\" + Qdw + \"\";};var Pg = \"e\\x6e\"" ascii
    $s17 = " \"\" + Iae + \"\";};function Hrr(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function BJf(q){var _112crap = \"s\"; retu" ascii
    $s18 = "QM + \"\";};function t(wCm){var _112crap = \"s\"; return \"\" + wCm + \"\";};function p(KVA){var _112crap = \"s\"; return \"\" +" ascii
    $s19 = " \"\";};function zc(TF){var _112crap = \"s\"; return \"\" + TF + \"\";};function K(Xux){var _112crap = \"s\"; return \"\" + Xux " ascii
    $s20 = "n uGQ(wj){var _112crap = \"s\"; return \"\" + wj + \"\";};function of(A2){var _112crap = \"s\"; return \"\" + A2 + \"\";};functi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}