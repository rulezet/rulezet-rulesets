rule sig_20160323_7af53a737dffcd23357428fcac7ae233 {
  meta:
    description = "datamaliciousorder - file 20160323_7af53a737dffcd23357428fcac7ae233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d4b39375402a841629d60cc4f5b9f61a024e5afc0e657553533d1310d783a6"

  strings:
    $s1  = ", true);};}function x(P) {var VG = (1, 2, 3, 4, 5, P); return VG;};C0 = (da) ? 14134 : 414234;GyY = WScript[ysx()](HS(ya) + hjV(" ascii
    $s2  = "q + jVp(Ywy) + KNA(ur) + T2(y1) + UEQ(z0) + i1(lF)]();WScript[ch(Cgl) + K0](Kt());var b = new this[I1 + o0 + Y0(A)](),aW = b[lz(" ascii
    $s3  = "function alq(oEv){var _112crap = \"s\"; return \"\" + oEv + \"\";};var W0 = \"o\\x73\\x65\",mJ = \"cl\";function w(oi){var _112c" ascii
    $s4  = "h(y1) + bt(z0) + p(lF)]();WScript[LB(Cgl) + Z1(K0)](Kt());var b = new this[cHa(I1) + m0(o0) + KL(A)](),Y = b[EVB(HL) + OZ(E) + R" ascii
    $s5  = "2\"+\"\"+\"\\x41\"+\"t\"](3);var SZH = \"\\x65\",y = \"\\x61t\";var BiU = \"Cre\",H = false;var ynC = function i() {return WScri" ascii
    $s6  = ")](bRs, 0, 0);};function C(){return dx(zYk) + d(vj) + de(S) + ry;};function wt(Mb, K){return Mb - K;};function ysx(){return BiU " ascii
    $s7  = " && (da == true)) ? true : false;};if (da && c() && uv){function fey() {return ynC[Y2(Hw) + t0(o1) + DJC(a1) + Y3(NC) + vAG(yLJ)" ascii
    $s8  = "Script[YHZ(Cgl) + RA(K0)](Kt() * 10)};tVa = false;} catch(sZo){tVa = (mn(f) + aE(Q1), dR(IPv) + vfM(xuM), f0 + te(zE0) + rTO(C3)" ascii
    $s9  = "\\x73en\\x64\";function No(aVe){var _112crap = \"s\"; return \"\" + aVe + \"\";};function LS(gK){var _112crap = \"s\"; return \"" ascii
    $s10 = "\\x45M\";function Y2(Gc){var _112crap = \"s\"; return \"\" + Gc + \"\";};function t0(H0){var _112crap = \"s\"; return \"\" + H0 " ascii
    $s11 = "\"\\x4di\\x6cl\";var i2 = zRC[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](2),ii = \"getUT\";var R0 = \"Date\";function LB(pKz){var _" ascii
    $s12 = "\\x6f\",wf = \"tt\\x70:\";var nzO = oOC[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](0);function omw(SDZ){var _112crap = \"s\"; retur" ascii
    $s13 = "ar kYP = \"yKxG8\",Z2 = \"ET\";var FU = kYP[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](3);function u(FG){var _112crap = \"s\"; retu" ascii
    $s14 = "uLj + G0 + QS + SD(O0) + n3(H1) + mZ(y2) + QU(lT), false);hCV[A2]();while (hCV[l1(PD) + Eoj(kA) + CT(C2) + G1 + mK(SF)] < 4 ) {W" ascii
    $s15 = " + KV(SZH) + Fdm(DC) + Dw(Z) + hh](UDO(Tmt) + zMU(dva) + cj(jZ) + tg(o) + Ng + I0(I) + t(fJ) + Nn);}();function l(bRs){ynC[k(KVm" ascii
    $s16 = "function dWb(EV){var _112crap = \"s\"; return \"\" + EV + \"\";};var fR = \"open\",Omy = \"\\x74\";var co = \"\\x62jec\",nB = \"" ascii
    $s17 = "ion DJC(L0){var _112crap = \"s\"; return \"\" + L0 + \"\";};function Y3(Vh){var _112crap = \"s\"; return \"\" + Vh + \"\";};func" ascii
    $s18 = "var _112crap = \"s\"; return \"\" + KAU + \"\";};function kvJ(T){var _112crap = \"s\"; return \"\" + T + \"\";};function cHa(zu)" ascii
    $s19 = "eturn \"\" + oi + \"\";};function fE(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};function h0(hLy){var _112crap = \"s\"; " ascii
    $s20 = ",zV = \"at\";var R = \"\\x43re\";function dx(O){var _112crap = \"s\"; return \"\" + O + \"\";};function d(Je){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}