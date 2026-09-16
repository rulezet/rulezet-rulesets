rule sig_20160323_abde85b8c39b538410cbcc959cd51f69 {
  meta:
    description = "datamaliciousorder - file 20160323_abde85b8c39b538410cbcc959cd51f69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc20f23f4074cdb5a75c0fa3efd374fe58c754b36cee6b0ef5e998f05258cf98"

  strings:
    $s1  = "function e2(JQ){var _112crap = \"s\"; return \"\" + JQ + \"\";};function SKG(B){var _112crap = \"s\"; return \"\" + B + \"\";};v" ascii
    $s2  = "x2(uxx), false);eg[Q1(lQb) + QB(osw)]();while (eg[qJg(PQP) + IBh + u2(ub)] < 4 ) {WScript[QYU(pD) + N0](aDw() * 10)};iq = false;" ascii
    $s3  = "C\\x72\\x65a\",yM = false;var dFh = function X() {return WScript[OSv + R0(D) + z(fF) + keS(ZUn) + JiB](c0(BQB) + rf(tZ) + az(p0)" ascii
    $s4  = ") + PrO(DCQ)](),K0 = x[N(phD) + qIT(Ec) + T1(vw) + F0 + RJJ(NvY) + E + BM(h0)]();WScript[pD + j1(N0)](aDw());var x = new this[Qx" ascii
    $s5  = " + Su(DCQ)](),yi = x[phD + rS(Ec) + TX(vw) + j0(F0) + NvY + E + h0]();WScript[Brx(pD) + x0(N0)](aDw());var x = new this[jcp(Qx) " ascii
    $s6  = "return Vij;};b = (yu) ? 14134 : 414234;Pze = WScript[QzP()](jz(o1) + FIa + G(P0) + R3(WF) + Id);WTx = Pze;R = (M) ? b : R;WTx[(W" ascii
    $s7  = " + p1 + C(o);};function vk(dn, l){return dn - l;};function QzP(){return F(OSv) + j(D) + h(fF) + e0(ZUn) + JiB;};/*@cc_on  @if (@" ascii
    $s8  = " _112crap = \"s\"; return \"\" + h2 + \"\";};function x2(Yn){var _112crap = \"s\"; return \"\" + Yn + \"\";};var dL = \"mKey\",u" ascii
    $s9  = "ue : false;};if (yu && iL() && M){function TiB() {return dFh[j2(s0) + vBo(Rzw) + mew(U0) + rQ(Q) + rgB(Pq) + EEy(hO) + XI(f0)](j" ascii
    $s10 = " 123313 * b + R; M = true; R = \"07t9gasdf76ags\" + 123313 * b + R; break;}}function iL() {return ((yu == M) && (yu == true)) ? " ascii
    $s11 = "\\x65\",BpO = \"cl\";function l1(K2){var _112crap = \"s\"; return \"\" + K2 + \"\";};function y1(w3){var _112crap = \"s\"; retur" ascii
    $s12 = "0){var _112crap = \"s\"; return \"\" + G0 + \"\";};function R3(y0){var _112crap = \"s\"; return \"\" + y0 + \"\";};var Id = \"" ascii
    $s13 = "bL){var _112crap = \"s\"; return \"\" + nbL + \"\";};var d0 = \"ll\",Tj = \"UtiEdg\";var zVt = \"MXYIvsyz\",h0 = zVt[\"charA\"+" ascii
    $s14 = "lAo + nr(Ew) + J(NOO));}();function nS(A){dFh[gd(S) + HH(kD) + Yho(mi)](A, 0, 0);};function tpN(){return LO(V) + UTf(t) + PC(ZJ)" ascii
    $s15 = "72\\x65a\";var P0 = \"\\x2eS\",FIa = \"\\x42\";var o1 = \"ADO\\x44\";function cbl(qe){var _112crap = \"s\"; return \"\" + qe + " ascii
    $s16 = " x3 + \"\";};function lek(u3){var _112crap = \"s\"; return \"\" + u3 + \"\";};var o2 = \"Gt3\",zw = \"e\";var QJw = o2[\"charA\"" ascii
    $s17 = "turn \"\" + dm + \"\";};function QB(p2){var _112crap = \"s\"; return \"\" + p2 + \"\";};var oe = \"ddozf\",osw = oe[\"charA\"+\"" ascii
    $s18 = "r _112crap = \"s\"; return \"\" + rh + \"\";};var XkL = \"n\",pR = \"i\\x6f\";var I0 = \"it\",tCS = \"pos\";function JlK(IDj){va" ascii
    $s19 = "\";};function Su(tM){var _112crap = \"s\"; return \"\" + tM + \"\";};function jcp(A0){var _112crap = \"s\"; return \"\" + A0 + " ascii
    $s20 = "nction mew(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function rQ(td){var _112crap = \"s\"; return \"\" + td + \"\";};f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}