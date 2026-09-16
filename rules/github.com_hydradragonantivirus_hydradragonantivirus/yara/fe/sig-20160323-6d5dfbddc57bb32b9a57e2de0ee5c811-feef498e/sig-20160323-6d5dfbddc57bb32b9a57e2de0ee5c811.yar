rule sig_20160323_6d5dfbddc57bb32b9a57e2de0ee5c811 {
  meta:
    description = "datamaliciousorder - file 20160323_6d5dfbddc57bb32b9a57e2de0ee5c811.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8530078c55ae15154bdf40705bf76a2d3bb748ba1138a0d075e4bb08a207add3"

  strings:
    $s1  = "function l(q2){var _112crap = \"s\"; return \"\" + q2 + \"\";};var KUM = \"o\\x73e\",qKl = \"cl\";function eDT(g0){var _112crap " ascii
    $s2  = "e0(Rat) + N + dQt(eE) + TT + yf(ytC), false);vr[Xh(G1)]();while (vr[i0(k0) + Ql(o) + I1(sH)] < 4 ) {WScript[h1(R0)](xb() * 10)};" ascii
    $s3  = "return iW;};m = (gK) ? 14134 : 414234;p = WScript[RzJ()](vzR + d1(iI) + LkH(xU) + QJH(L0));OHJ = p;mDM = (X) ? m : mDM;OHJ[(Gkg(" ascii
    $s4  = " this[Ct(A0)](),CqD = DD[up(F) + a0(otO) + KM + UA + Wc + VF(qA) + f0(kWV) + q(NcW) + Umn(duD)]();WScript[TJ(R0)](xb());var DD =" ascii
    $s5  = "= WScript[H0(fmb) + yol(t) + Yx(YV) + KR](OHJ); var Vi = true; while (Vi){try {vr[co + Bqp(HT)](C + pb(H2), Hk + a2(Vv) + cEG + " ascii
    $s6  = "t = \"\\x65ate\",fmb = \"Cr\";var JHd = false,m0 = function je() {return WScript[fmb + PNu(t) + QdS(YV) + c(KR)](v(cr) + m1(Mo) " ascii
    $s7  = "tion FIP() {return ((gK == X) && (gK == true)) ? true : false;};if (gK && FIP() && X){function S() {return m0[Qp(KBE) + kVm(De) " ascii
    $s8  = "\"\" + QqJ + \"\";};var sH = \"ate\",o = \"st\";var k0 = \"ready\";function Xh(eFc){var _112crap = \"s\"; return \"\" + eFc + \"" ascii
    $s9  = "Y(L) + IC + cN(K0);};function H(CAd, G){return CAd - G;};function RzJ(){return pgn(fmb) + t + aby(YV) + e(KR);};/*@cc_on  @if (@" ascii
    $s10 = "ion Ec(vT){var _112crap = \"s\"; return \"\" + vT + \"\";};function EJ(qq){var _112crap = \"s\"; return \"\" + qq + \"\";};funct" ascii
    $s11 = "ction Bqp(sU){var _112crap = \"s\"; return \"\" + sU + \"\";};function Gkg(B){var _112crap = \"s\"; return \"\" + B + \"\";};var" ascii
    $s12 = "2crap = \"s\"; return \"\" + t0 + \"\";};function Pf(fu){var _112crap = \"s\"; return \"\" + fu + \"\";};var c0 = \"mWQ\",Z = \"" ascii
    $s13 = "ction h1(eY){var _112crap = \"s\"; return \"\" + eY + \"\";};var R0 = \"S\\x6ceep\";function qM(G0){var _112crap = \"s\"; return" ascii
    $s14 = " + \"\";};function QdS(QJ){var _112crap = \"s\"; return \"\" + QJ + \"\";};function c(fm){var _112crap = \"s\"; return \"\" + fm" ascii
    $s15 = "a\\x74\\x65\";function H1(bT){var _112crap = \"s\"; return \"\" + bT + \"\";};function TJ(d){var _112crap = \"s\"; return \"\" +" ascii
    $s16 = "= \"ex\\x65\",T0 = \"\\x72z6\\x2e\";var q0 = \"ZPbZ\",gn = \"43\";function QW(Xpc){var _112crap = \"s\"; return \"\" + Xpc + \"" ascii
    $s17 = " \"\\x25/\";var x0 = \"M\\x50\",Bhr = \"TE\";var S0 = Cg[\"cha\"+\"\\x72\"+\"At\"](3);function Qp(a1){var _112crap = \"s\"; retu" ascii
    $s18 = "t\"](5),AkF = \"pe\";var U1 = \"o\";function d1(TM){var _112crap = \"s\"; return \"\" + TM + \"\";};function LkH(QYQ){var _112cr" ascii
    $s19 = "\"; return \"\" + tvO + \"\";};var lq = \"n\",uk = \"t\\x69o\";var r0 = \"posi\";function U2(F1){var _112crap = \"s\"; return \"" ascii
    $s20 = "var _112crap = \"s\"; return \"\" + F0 + \"\";};function Uz(GKk){var _112crap = \"s\"; return \"\" + GKk + \"\";};function GU(p0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}