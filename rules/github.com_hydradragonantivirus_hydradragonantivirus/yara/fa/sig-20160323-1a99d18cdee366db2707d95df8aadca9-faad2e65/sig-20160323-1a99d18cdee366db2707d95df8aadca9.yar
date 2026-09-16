rule sig_20160323_1a99d18cdee366db2707d95df8aadca9 {
  meta:
    description = "datamaliciousorder - file 20160323_1a99d18cdee366db2707d95df8aadca9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f2e321fc7fb953095755d31c95cfb0724a0cd2025e10d6219a1d6e79f9b3f18"

  strings:
    $s1  = "function JO(ct){var _112crap = \"s\"; return \"\" + ct + \"\";};function K(TTi){var _112crap = \"s\"; return \"\" + TTi + \"\";}" ascii
    $s2  = "0) + pr0, true);};}function SW(ce) {var i = (1, 2, 3, 4, 5, ce); return i;};PD = (qu) ? 14134 : 414234;E = WScript[T()](eo(n2) +" ascii
    $s3  = "H(n0) + f0(s1)]();WScript[S(C1)](U0());var u = new this[boq](),UW = u[VJd(bF) + TNa(kNN) + AY + D(c) + VF + YJ(iU) + V(n0) + s1]" ascii
    $s4  = "\"; return \"\" + T0 + \"\";};var Sh = \"HTTP\",BpY = \".XML\";var qFy = \"\\x4c2\",ik = \"XM\";var rY = \"MS\";function WC(p){v" ascii
    $s5  = " function vcD() {return WScript[ou(ulo) + Bqc + nry(SC)](OZt(aO) + sRD(PDi) + s0(us) + bLU(EUk) + DDG(cJ) + aP);}();function aN(" ascii
    $s6  = "();WScript[EFP(C1)](U0());var u = new this[TWF(boq)](),Yg = u[WN(bF) + kNN + AY + c + uYJ(VF) + RLx(iU) + jU(n0) + jSD(s1)]();va" ascii
    $s7  = "y3) + EqW;}; y = Fqe(); yfY = WScript[m(ulo) + Ku(Bqc) + SC](y); var EQ = true; while (EQ){try {yfY[Bqm(Qjv) + zQI](G1(dhn) + b0" ascii
    $s8  = "Ky){oe[WC(vO) + aXw](Ky, 0, 0);};function Fqe(){return aiJ(rY) + Nh(ik) + v(qFy) + BpY + Sh;};function gpI(QKl, C){return QKl - " ascii
    $s9  = " * PD + XEQ; break;}}function N() {return ((qu == n) && (qu == true)) ? true : false;};if (qu && N() && n){function U() {return " ascii
    $s10 = " FZ(LM) + w(dK)] < 4 ) {WScript[L(C1)](U0() * 10)};EQ = false;} catch(Zax){EQ = (CGM, Ln(Ip) + qOO(Zu) + i2(vnU), i3(vh) + KTl(v" ascii
    $s11 = "; return \"\" + M0 + \"\";};var H0 = \"hNh%63ts\",s3 = \"igG/\";var vL = s3[\"char\"+\"\\x41\"+\"t\"](3),Bc = \"T\\x45MP%\";var " ascii
    $s12 = " \"\" + j + \"\";};function TNa(BWo){var _112crap = \"s\"; return \"\" + BWo + \"\";};function D(j0){var _112crap = \"s\"; retur" ascii
    $s13 = "(s2){var _112crap = \"s\"; return \"\" + s2 + \"\";};function SIW(o){var _112crap = \"s\"; return \"\" + o + \"\";};var Y0 = \"n" ascii
    $s14 = "turn \"\" + Hv + \"\";};function sRD(vhA){var _112crap = \"s\"; return \"\" + vhA + \"\";};function s0(t0){var _112crap = \"s\";" ascii
    $s15 = "\"; return \"\" + p + \"\";};var jZ = \"51ugniS9\",aXw = jZ[\"char\"+\"\\x41\"+\"t\"](4);var vO = \"Ru\";function OZt(Hv){var _1" ascii
    $s16 = "+ L0 + \"\";};var WlZ = \"ET\",dhn = \"G\";function Bqm(hH){var _112crap = \"s\"; return \"\" + hH + \"\";};function ixN(M1){var" ascii
    $s17 = "\"s\"; return \"\" + M1 + \"\";};function edv(Cc){var _112crap = \"s\"; return \"\" + Cc + \"\";};var zQI = \"n\",Qjv = \"ope\";" ascii
    $s18 = "N(Sa){var _112crap = \"s\"; return \"\" + Sa + \"\";};function uYJ(GF){var _112crap = \"s\"; return \"\" + GF + \"\";};function " ascii
    $s19 = "aNJ = \"\\x68\\x74\\x74p\";function G1(Kfu){var _112crap = \"s\"; return \"\" + Kfu + \"\";};function b0(L0){var _112crap = \"s" ascii
    $s20 = "\"T\",kNN = \"et\\x55\";var bF = QPh[\"char\"+\"\\x41\"+\"t\"](0);function TWF(y0){var _112crap = \"s\"; return \"\" + y0 + \"\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}