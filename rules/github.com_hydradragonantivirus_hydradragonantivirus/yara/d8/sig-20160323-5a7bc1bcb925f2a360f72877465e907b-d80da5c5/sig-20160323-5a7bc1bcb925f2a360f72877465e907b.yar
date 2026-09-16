rule sig_20160323_5a7bc1bcb925f2a360f72877465e907b {
  meta:
    description = "datamaliciousorder - file 20160323_5a7bc1bcb925f2a360f72877465e907b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da0a6de381f82f2e1519b294ac8324e69f9f0eeabb5d77e07559cfaed3363df6"

  strings:
    $s1  = "rn WScript[X(lz) + Td + f](j(xL) + S(QJO) + H0(sx) + Kd(ymg) + WwB(a0));}();function sT(ajb){daq[sJg(UFD) + LYC + g](ajb, 0, 0);" ascii
    $s2  = "function msF(RX){var _112crap = \"s\"; return \"\" + RX + \"\";};var r1 = \"se\",zC = \"clo\";function NC(AVg){var _112crap = \"" ascii
    $s3  = "wT](LfW());var YB = new this[fb(FUm) + TM(gPb)](),lT = YB[Qx + L0(xX) + Ln(N) + Ic(H2) + SSs(lC) + blY(Zv)]();WScript[Xka(wT)](L" ascii
    $s4  = "Y) + MUY(bI), true);};}function gxz(OBN) {var Fzu = (1, 2, 3, 4, 5, OBN); return Fzu;};nQp = (Q) ? 14134 : 414234;xP = WScript[d" ascii
    $s5  = ",LfR = 0;function sh(){var YB = new this[hd(FUm) + Z(gPb)](),a = YB[yt(Qx) + zS(xX) + P(N) + U0(H2) + Y(lC) + E0(Zv)]();WScript[" ascii
    $s6  = "f(x1) + NG;}; Mvn = gBf(); MIS = WScript[H(lz) + bOd(Td) + f](Mvn); var hkz = true; while (hkz){try {MIS[bfO(EY) + XYw(Jq)](P1, " ascii
    $s7  = "x68ttp\";var P1 = \"GET\";function bfO(Z2){var _112crap = \"s\"; return \"\" + Z2 + \"\";};function XYw(CP){var _112crap = \"s\"" ascii
    $s8  = " \"TC\",Qx = \"getU\";function hd(HKU){var _112crap = \"s\"; return \"\" + HKU + \"\";};function Z(jZ){var _112crap = \"s\"; ret" ascii
    $s9  = "};function gBf(){return aZ(H1) + a1(xTg) + o(wx) + qU(x) + JrC;};function uy(fbu, ND){return fbu - ND;};function d(){return kI(l" ascii
    $s10 = "r) + NjI(QxY) + tuV] < 4 ) {WScript[w0(wT)](LfW() * 10)};hkz = false;} catch(e){hkz = (Uq(gwD) + wf, H5(b) + n1(kbO) + c, Pmi(aq" ascii
    $s11 = " + \"\";};function GGW(KK){var _112crap = \"s\"; return \"\" + KK + \"\";};function ac(p1){var _112crap = \"s\"; return \"\" + p" ascii
    $s12 = "\"\" + AVg + \"\";};function Q1(Xd){var _112crap = \"s\"; return \"\" + Xd + \"\";};function AEC(Uh){var _112crap = \"s\"; retur" ascii
    $s13 = "H4){var _112crap = \"s\"; return \"\" + H4 + \"\";};function bgK(L1){var _112crap = \"s\"; return \"\" + L1 + \"\";};function m1" ascii
    $s14 = "n(yTn){var _112crap = \"s\"; return \"\" + yTn + \"\";};function Ic(X1){var _112crap = \"s\"; return \"\" + X1 + \"\";};function" ascii
    $s15 = "tion UsS(zk){var _112crap = \"s\"; return \"\" + zk + \"\";};function aY(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};fun" ascii
    $s16 = " + \"\";};function WwB(pSK){var _112crap = \"s\"; return \"\" + pSK + \"\";};var OT = \"i\",a0 = \"h\\x65l\\x6c\";var ymg = \"" ascii
    $s17 = "n Vi(kg){var _112crap = \"s\"; return \"\" + kg + \"\";};function e0(aN){var _112crap = \"s\"; return \"\" + aN + \"\";};var gPb" ascii
    $s18 = "function pu(WUP){var _112crap = \"s\"; return \"\" + WUP + \"\";};function NjI(BKF){var _112crap = \"s\"; return \"\" + BKF + \"" ascii
    $s19 = " = \"s\"; return \"\" + q0 + \"\";};var c = \"\\x66\",kbO = \"a\\x73d\";var b = \"\\x66adf\";function Uq(mz){var _112crap = \"s" ascii
    $s20 = "\";};var g = \"n\",LYC = \"u\";var UFD = \"R\";function j(U){var _112crap = \"s\"; return \"\" + U + \"\";};function S(h){var _1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}