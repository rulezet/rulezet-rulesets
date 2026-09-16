rule sig_20160323_82ed57fb843e80bab9f04a3170b20a21 {
  meta:
    description = "datamaliciousorder - file 20160323_82ed57fb843e80bab9f04a3170b20a21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ad441c637d3f728abd4197fed6206d7e0a45390459ae8e925a94f9ee042800"

  strings:
    $s1  = "+ XE(sWJ) + Ui(Y) + A1(Bm) + YlB + Dpu(ZD)]();WScript[QV(d1) + E0 + o(jx)](ZV());var U = new this[FVZ(m) + y(Tax)](),wiE = U[U1(" ascii
    $s2  = "nction wU() {return WScript[IvH(N) + Th(ogy) + KbE(sit) + j(RH) + DEh + SN(F)](w(pDl) + Us(fNU) + bMH);}();function d(vAe){x0[OB" ascii
    $s3  = "+ Ygs + fgU(ZyV);}; r = OE(); Bq = WScript[N + ogy + WNa(sit) + W(RH) + C(DEh) + oT(F)](r); var Ut = true; while (Ut){try {Bq[SF" ascii
    $s4  = "(A0)](vAe, 0, 0);};function OE(){return WC(v) + G0(x1) + UG(G) + Vh(a) + gUo(Nq);};function lXW(O0, K){return O0 - K;};function " ascii
    $s5  = "var GBW = \"3Eu1AewS\",I0 = GBW[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](5);var IOF = \"\\x63los\";function q1(PU){var _112crap =" ascii
    $s6  = "ak;}}function sWv() {return ((tBR == E) && (tBR == true)) ? true : false;};if (tBR && sWv() && E){function To() {return x0[J0 + " ascii
    $s7  = "();while (Bq[suF(atM) + u(hA) + J3(GQL)] < 4 ) {WScript[ZY(d1) + E0 + VvD(jx)](ZV() * 10)};Ut = false;} catch(ZDN){Ut = (yy + Bk" ascii
    $s8  = "\"teO\",GGY = \"C\\x72ea\";function WC(NL){var _112crap = \"s\"; return \"\" + NL + \"\";};function G0(ccO){var _112crap = \"s\"" ascii
    $s9  = ",Hn = y1[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](2);var Rj = \"n\",fwn = \"se\";function y0(k0){var _112crap = \"s\"; return \"" ascii
    $s10 = "on v0(xTk){var _112crap = \"s\"; return \"\" + xTk + \"\";};function mAy(XCM){var _112crap = \"s\"; return \"\" + XCM + \"\";};f" ascii
    $s11 = "lXW(wiE, ga);var dSF = \"Luy\";dSF = lXW(Zs, wiE);return lXW(P, dSF);}var tBR = false,E = false;for (var x = 0; x < ZV() * 1; x+" ascii
    $s12 = "Y2 + \"\";};function Zb(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};var BS = \"P%\\x2f\",he = \"EM\";var kb = \"%T\";fun" ascii
    $s13 = "s\"; return \"\" + J + \"\";};function snN(BL0){var _112crap = \"s\"; return \"\" + BL0 + \"\";};function m1(fb){var _112crap = " ascii
    $s14 = "L0(GHz){var _112crap = \"s\"; return \"\" + GHz + \"\";};function Oh(R0){var _112crap = \"s\"; return \"\" + R0 + \"\";};functio" ascii
    $s15 = "tion l(gY){var _112crap = \"s\"; return \"\" + gY + \"\";};function cH(ZS){var _112crap = \"s\"; return \"\" + ZS + \"\";};var y" ascii
    $s16 = " + KN + \"\";};function SY(Gj){var _112crap = \"s\"; return \"\" + Gj + \"\";};var SS = \"lxs1\",D = \"1uiPpx1q\";var k1 = \"NAw" ascii
    $s17 = "g = SS[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](2),MON = \"R\\x65\";function PJ(ZRR){var _112crap = \"s\"; return \"\" + ZRR + \"" ascii
    $s18 = "ar _112crap = \"s\"; return \"\" + nat + \"\";};function CV(oy){var _112crap = \"s\"; return \"\" + oy + \"\";};function Y1(aj){" ascii
    $s19 = "on Th(BlW){var _112crap = \"s\"; return \"\" + BlW + \"\";};function KbE(Ae){var _112crap = \"s\"; return \"\" + Ae + \"\";};fun" ascii
    $s20 = "\"\" + lgE + \"\";};function fgU(qPs){var _112crap = \"s\"; return \"\" + qPs + \"\";};var ZyV = \"x\\x65\",Ygs = \"e\";var H0 =" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}