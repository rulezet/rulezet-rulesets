rule sig_20160324_3116b98970699bdcf029944dce506044 {
  meta:
    description = "datamaliciousorder - file 20160324_3116b98970699bdcf029944dce506044.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4f0d866eeb26b71603677eaba411f5e317a4c7e369beca5885c7b9ac98c1e1d"

  strings:
    $s1  = "function raT(yB){var _112crap = \"s\"; return \"\" + yB + \"\";};var k1 = \"s\\x65\",L2 = \"clo\";function qmr(plN){var _112crap" ascii
    $s2  = "nction afB(I) {var vd = (1, 2, 3, 4, 5, I); return vd;};Q = (Uo) ? 14134 : 414234;t = WScript[mDo()](C1(Rs) + d1(TI) + c3(B0) + " ascii
    $s3  = "WY = \"c\",x = \"\\x6ae\";var Xzl = \"ateO\\x62\",ej = \"Cre\";var j = false,U = function lz() {return WScript[LKP(ej) + WEo(Xzl" ascii
    $s4  = "function raT(yB){var _112crap = \"s\"; return \"\" + yB + \"\";};var k1 = \"s\\x65\",L2 = \"clo\";function qmr(plN){var _112crap" ascii
    $s5  = ",Jh0 = \"\\x65nd\";var iEx = ANg[\"cha\"+\"\\x72\"+\"At\"](5);function uSG(A1){var _112crap = \"s\"; return \"\" + A1 + \"\";};f" ascii
    $s6  = "{return eRX(O) + TD(Wn) + Qp(a0) + eaT(WeM) + r(Yc);};function OTj(HFo, CVp){return HFo - CVp;};function mDo(){return KH(ej) + m" ascii
    $s7  = " == zgo) && (Uo == true)) ? true : false;};if (Uo && kaf() && zgo){function N() {return U[DQ + mb + NV(MdO) + L0 + K0(S0) + pLv " ascii
    $s8  = "\".c\";var jOm = \"afr\\x70\",Ydz = \"harm\";var lct = Xl[\"cha\"+\"\\x72\"+\"At\"](4),rqe = \"//\";var y = \"h\\x74tp:\";functi" ascii
    $s9  = " + X2](Zq());var b = new this[kHs](),lX = b[I0(qRe) + azm + c(Et) + jp + oc(EqM) + OtH(CA)]();WScript[Q0(Ny) + oK(X2)](Zq());var" ascii
    $s10 = " = 0,GwK = 0;function X(){var b = new this[z0(kHs)](),D0 = b[L(qRe) + azm + N0(Et) + Xwz(jp) + h(EqM) + d(CA)]();WScript[qcR(Ny)" ascii
    $s11 = " + Wlc + \"\";};function JIc(K){var _112crap = \"s\"; return \"\" + K + \"\";};var X2 = \"e\\x65\\x70\",Ny = \"Sl\";function L(t" ascii
    $s12 = "rn \"\" + T + \"\";};function hXH(Nv){var _112crap = \"s\"; return \"\" + Nv + \"\";};var gz = \"AYXtmg\",p = gz[\"cha\"+\"\\x72" ascii
    $s13 = "2crap = \"s\"; return \"\" + BDG + \"\";};function Siq(SsS){var _112crap = \"s\"; return \"\" + SsS + \"\";};function crf(ZZw){v" ascii
    $s14 = "s\"; return \"\" + ITq + \"\";};function MI0(bUz){var _112crap = \"s\"; return \"\" + bUz + \"\";};function TYB(uv){var _112crap" ascii
    $s15 = "p = \"s\"; return \"\" + UC + \"\";};function ZY(kv){var _112crap = \"s\"; return \"\" + kv + \"\";};function HrK(C0){var _112cr" ascii
    $s16 = "n PK(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};var PW = \"n\",l0 = \"\\x74\\x69\\x6f\";var YCe = \"i\",qBS = \"pos\";f" ascii
    $s17 = " \"s\"; return \"\" + KOE + \"\";};function ojd(oZ){var _112crap = \"s\"; return \"\" + oZ + \"\";};function gcJ(T){var _112crap" ascii
    $s18 = "sWY + hXH(p)](SHI); var Dnu = true; while (Dnu){try {q[n0(w)](dSZ(ZUz), uSG(y) + rqe + lct + n1(Ydz) + APd(jOm) + tHa(Llm) + ZY(" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + nzG + \"\";};function e(at){var _112crap = \"s\"; return \"\" + at + \"\";};function S(KOE){va" ascii
    $s20 = "var _112crap = \"s\"; return \"\" + NTX + \"\";};function RI0(oLc){var _112crap = \"s\"; return \"\" + oLc + \"\";};function c4(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}