rule sig_20160323_d69ed99d134601a208c7563b9fc50299 {
  meta:
    description = "datamaliciousorder - file 20160323_d69ed99d134601a208c7563b9fc50299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa9b7e8645a3b109bcbe82f70ad8164d6688236a08768e2a4ef251d5298a558"

  strings:
    $s1  = "function YZl(eNH){var _112crap = \"s\"; return \"\" + eNH + \"\";};var PM = \"se\",Tlc = \"cl\\x6f\";function JuJ(Rz){var _112cr" ascii
    $s2  = "D0(ZTJ) + sGl(GkV);}; E = mLn(); MZN = WScript[fqG(d0) + mQ(HV) + xtW(d1) + sB(NX) + JYm(r)](E); var F = true; while (F){try {MZ" ascii
    $s3  = "turn WScript[iU(d0) + s(HV) + nH(d1) + NX + oDp(r)](Ix(sG) + J(Nu) + IPl + vcd(sg) + Y0(i0) + gm(GZ));}();function Y(yH){dqu[qw(" ascii
    $s4  = "), false);MZN[WsA(dtF)]();while (MZN[Cl(t0) + JCm(y2) + PT(wTr) + fS(Cuc)] < 4 ) {WScript[mMd(G) + tTK(Kz)](lL() * 10)};F = fals" ascii
    $s5  = "DR)]();WScript[G + WY(Kz)](lL());var d = new this[dEj + vb(DrE) + g(yet)](),gCm = d[Hur + Xz(r1) + t + kkY(lOU) + ppu(DR)]();WSc" ascii
    $s6  = "Hrk){var _112crap = \"s\"; return \"\" + Hrk + \"\";};var l1 = \"xJje1\",VPL = \"\\x6e\";var vyT = l1[\"c\"+\"\\x68\"+\"arAt\"](" ascii
    $s7  = " = \"GET\";function Q2(QAt){var _112crap = \"s\"; return \"\" + QAt + \"\";};function b0(DE){var _112crap = \"s\"; return \"\" +" ascii
    $s8  = "\";};function fS(ogb){var _112crap = \"s\"; return \"\" + ogb + \"\";};var wE = \"e\",Cuc = wE[\"c\"+\"\\x68\"+\"arAt\"](0);var " ascii
    $s9  = "nQ = \"://n\",x = \"tp\";var Fl = xO[\"c\"+\"\\x68\"+\"arAt\"](1),MM = \"h\";function sp(HU){var _112crap = \"s\"; return \"\" +" ascii
    $s10 = "{var _112crap = \"s\"; return \"\" + Zmj + \"\";};var L = \"Aioc1t\",n1 = \"eTgIT3\";var yet = n1[\"c\"+\"\\x68\"+\"arAt\"](0),D" ascii
    $s11 = "\"; return \"\" + sq + \"\";};var KhZ = \"uS62\",Kz = \"l\\x65e\\x70\";var G = KhZ[\"c\"+\"\\x68\"+\"arAt\"](1);function f0(sT){" ascii
    $s12 = "\"\\x68\"+\"arAt\"](1),sg = \".S\";var IPl = \"p\\x74\",Nu = \"\\x69\";var sG = \"WScr\";function iU(tt){var _112crap = \"s\"; r" ascii
    $s13 = "Rxq = xy[\"c\"+\"\\x68\"+\"arAt\"](3),RfM = \"Dat\";function WY(d2){var _112crap = \"s\"; return \"\" + d2 + \"\";};function gf(" ascii
    $s14 = "uY) + B(H)](yH, 0, 0);};function mLn(){return Mk + Vk(BTj) + Mh(RTX) + Uh;};function Ja(AIp, n0){return AIp - n0;};function ZY()" ascii
    $s15 = ";}}function Ocs() {return ((i == DzX) && (i == true)) ? true : false;};if (i && Ocs() && DzX){function Uuq() {return dqu[d3 + bs" ascii
    $s16 = "+\"arAt\"](5);var dEj = \"D\\x61\",f = \"\\x63\\x74\";var vR = \"b\\x6ae\",GR = \"\\x65O\";var a = \"e\\x61\\x74\",KZ = \"Cr\";f" ascii
    $s17 = "var xiP = \"VozEl\",rzZ = \"e\";var V0 = \"F\\x69l\",h1 = xiP[\"c\"+\"\\x68\"+\"arAt\"](1);var jB = \"T\",mxm = \"\\x65\";var sT" ascii
    $s18 = " e0 = \"D\",Z0 = \"ADO\";function nVZ(aY){var _112crap = \"s\"; return \"\" + aY + \"\";};function VAl(eCB){var _112crap = \"s\"" ascii
    $s19 = "eO(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};function Up(uc){var _112crap = \"s\"; return \"\" + uc + \"\";};function " ascii
    $s20 = "3\\x70\";function XA(z1){var _112crap = \"s\"; return \"\" + z1 + \"\";};function va(wE0){var _112crap = \"s\"; return \"\" + wE" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}