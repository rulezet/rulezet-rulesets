rule sig_20160323_5cb56c3e0bd159ff2e712a4c3f5f1d67 {
  meta:
    description = "datamaliciousorder - file 20160323_5cb56c3e0bd159ff2e712a4c3f5f1d67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1fb9555933b21c0425e942c03c590b19f810824ffd8520597450e259e6870dd"

  strings:
    $s1  = "function zyT(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};var odU = \"clo\\x73\\x65\";function e(HVX){var _112crap = \"s" ascii
    $s2  = "WbV[\"c\"+\"\\x68\"+\"arAt\"](2),hoY = \"C\\x4d\";var r0 = \"getUT\",og = \"\\x44at\\x65\";function Az(YPr){var _112crap = \"s\"" ascii
    $s3  = " + V0(L) + dpV + CUT(l)]();WScript[Az(K1) + QO](mt());var taP = new this[UX(Gfr) + px(w) + gaZ(A)](),vC = taP[RGP(pL) + PhI(mo) " ascii
    $s4  = "+ fh(jq) + Rj(COk) + FI(L) + K0(dpV) + iy(l)]();WScript[K1 + Xh(QO)](mt());var taP = new this[Z(Gfr) + n0(w) + Ln(A)](),Dk = taP" ascii
    $s5  = ", 2, 3, 4, 5, Y); return GW;};FFy = (Q) ? 14134 : 414234;NRX = WScript[M()](Jm + i1(QeQ) + cHI(hH));V = NRX;DST = (NKJ) ? FFy : " ascii
    $s6  = " \"\\x65\\x61teO\",dzu = \"Cr\";var RE = false,eu = function iCC() {return WScript[dzu + dO(VEV) + Dy(K) + yZ](a(Tl) + RO + tx +" ascii
    $s7  = "+\"\\x68\"+\"arAt\"](3);var SbO = \"sitio\",SF = \"p\\x6f\";function Ff(hk){var _112crap = \"s\"; return \"\" + hk + \"\";};func" ascii
    $s8  = "ar jq = SAo[\"c\"+\"\\x68\"+\"arAt\"](3),mo = \"tU\\x54C\";var pL = \"ge\";function IIv(iP){var _112crap = \"s\"; return \"\" + " ascii
    $s9  = "+\"arAt\"](1),Eyq = \"s\\x65\";function tFt(z){var _112crap = \"s\"; return \"\" + z + \"\";};function tiC(lN){var _112crap = \"" ascii
    $s10 = "rn \"\" + V2 + \"\";};function XfB(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};var Lb = \"mWaW6RF\",soK = Lb[\"c\"+\"\\x" ascii
    $s11 = " _112crap = \"s\"; return \"\" + uW + \"\";};var fH = \"GET\";function CH(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};fu" ascii
    $s12 = "unction RJn(Z2){var _112crap = \"s\"; return \"\" + Z2 + \"\";};function COM(W2){var _112crap = \"s\"; return \"\" + W2 + \"\";}" ascii
    $s13 = "yY){uFb = (yGD(HF) + RJn(NK) + COM(vhU), KRH + L2(X0) + vhJ(zVu), xUi + Xxn(pmb) + XfB(soK), true);};}function T(Y) {var GW = (1" ascii
    $s14 = "Fy + DST; NKJ = true; DST = \"07t9gasdf76ags\" + 123313 * FFy + DST; break;}}function sT() {return ((Q == NKJ) && (Q == true)) ?" ascii
    $s15 = "rue : false;};if (Q && sT() && NKJ){function g() {return eu[ASw(dce) + Ct + j0 + mk + eZk + Wc(R0) + s(zS) + hL(qG0)](Hyw(N2) + " ascii
    $s16 = "z) + ur, false);C[Ax(Eyq) + d(LQ) + xoI]();while (C[JMM + yKw + Z1(x1)] < 4 ) {WScript[K1 + QO](mt() * 10)};uFb = false;} catch(" ascii
    $s17 = "\\x61st\\x61\",k1 = \":\\x2f/\";var f = \"t\\x70\",lER = JM[\"c\"+\"\\x68\"+\"arAt\"](4);var vbq = YFp[\"c\"+\"\\x68\"+\"arAt\"]" ascii
    $s18 = "lr04\",vhU = \"f\\x61\";var NK = Ew[\"c\"+\"\\x68\"+\"arAt\"](0),HF = \"as\";var sN = \"ep\",Pj = \"\\x65\";var RP = \"\\x53l\";" ascii
    $s19 = "\"+\"\\x68\"+\"arAt\"](5),Gfr = \"D\";var Sr = \"t\",rV = \"ec\";var N0 = \"\\x65Ob\\x6a\",Q0 = \"Crea\\x74\";function QVo(kWh){" ascii
    $s20 = " + HVX + \"\";};function G0(eg){var _112crap = \"s\"; return \"\" + eg + \"\";};function Go(xC){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}