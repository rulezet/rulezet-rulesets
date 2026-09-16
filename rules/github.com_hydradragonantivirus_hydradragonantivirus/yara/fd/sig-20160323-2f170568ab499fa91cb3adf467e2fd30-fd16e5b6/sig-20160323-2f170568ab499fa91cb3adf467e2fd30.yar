rule sig_20160323_2f170568ab499fa91cb3adf467e2fd30 {
  meta:
    description = "datamaliciousorder - file 20160323_2f170568ab499fa91cb3adf467e2fd30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2205cee5a75c7bd761c938199dbee09b8e0d050749486e4aaf4e7d6f061c7312"

  strings:
    $s1  = "function ys(m2){var _112crap = \"s\"; return \"\" + m2 + \"\";};function Z2(iN){var _112crap = \"s\"; return \"\" + iN + \"\";};" ascii
    $s2  = "kM = C[pdz(M) + Z1(bh) + h + Xil(C0) + R1(cOo) + VX(P0) + JzL + BK(DN)]();WScript[h0(tFp) + IeN](qq());var C = new this[Txl(hCd)" ascii
    $s3  = "+ rw(Kiw) + vaR(H1) + wt(yJi) + oi(KAg) + ew(D0) + A1(jM), false);ei[l2(JjV) + wj]();while (ei[ow(e0) + rR0(qL)] < 4 ) {WScript[" ascii
    $s4  = " A = zx(); ei = WScript[w + xz + tOv(Y)](A); var aQJ = true; while (aQJ){try {ei[pU0 + Mat(nR)](J(f2), Pxj(PXp) + A0 + FLT(mDC) " ascii
    $s5  = "ar Y = \"jec\\x74\",xz = \"a\\x74e\\x4fb\";var w = \"\\x43r\\x65\",P = false;var Spj = function R0() {return WScript[Ql(w) + q(x" ascii
    $s6  = "tion R(EG) {var XI = (1, 2, 3, 4, 5, EG); return XI;};mph = (O) ? 14134 : 414234;m = WScript[dx()](tVJ(F1) + DNz(n0) + dg + INk " ascii
    $s7  = "](),mA = C[M + Z0(bh) + wde(h) + C0 + dV(cOo) + j0(P0) + Ac(JzL) + MaO(DN)]();WScript[tFp + IeN](qq());var C = new this[hCd](),q" ascii
    $s8  = "= cmm[\"c\"+\"\\x68\"+\"arAt\"](3);function BYZ(ius){var _112crap = \"s\"; return \"\" + ius + \"\";};var YA = \"exe\",cC = \"I." ascii
    $s9  = "_112crap = \"s\"; return \"\" + D1 + \"\";};var ts = \"zt9o2\",ZPx = \"yp\\x65\";var zJX = ts[\"c\"+\"\\x68\"+\"arAt\"](1),OoR =" ascii
    $s10 = "\",FC = S1[\"c\"+\"\\x68\"+\"arAt\"](0);var jEM = \"writ\";function LIr(eb){var _112crap = \"s\"; return \"\" + eb + \"\";};func" ascii
    $s11 = "rAt\"](0),h = \"M\\x69\";var bh = \"\\x54\\x43\",M = \"g\\x65tU\";function Txl(tP){var _112crap = \"s\"; return \"\" + tP + \"\"" ascii
    $s12 = "\" + KnC + \"\";};var o = \"dEeC%TU\",mP = \"%/\";var T0 = \"\\x45M\\x50\",NgX = \"\\x54\";var cuV = o[\"c\"+\"\\x68\"+\"arAt\"]" ascii
    $s13 = "rAt\"](0),dg = ya0[\"c\"+\"\\x68\"+\"arAt\"](0);var n0 = \"\\x2e\",F1 = \"A\\x44ODB\";function ox(maa){var _112crap = \"s\"; ret" ascii
    $s14 = "Pb = \"pons\",DM = \"es\";var olI = JKV[\"c\"+\"\\x68\"+\"arAt\"](1);function Cvs(k){var _112crap = \"s\"; return \"\" + k + \"" ascii
    $s15 = "Eyj) + OeO(Jua) + LL(Xie);};function Ly(AnT, K){return AnT - K;};function dx(){return KaB(w) + Wu(xz) + FAT(Y);};/*@cc_on  @if (" ascii
    $s16 = " ((O == kl) && (O == true)) ? true : false;};if (O && l() && kl){function V() {return Spj[fXe + s(af0) + sT(Fi) + vzw(v0) + wn +" ascii
    $s17 = "A[\"c\"+\"\\x68\"+\"arAt\"](1);var y1 = \"asdf\",i2 = \"e8u\";var o0 = \"\\x65\\x70\",T1 = i2[\"c\"+\"\\x68\"+\"arAt\"](0);var w" ascii
    $s18 = " Waj + \"\";};function BMD(t1){var _112crap = \"s\"; return \"\" + t1 + \"\";};var rCM = \"l\\x65\",HU = \"i\";var y2 = \"eToF\"" ascii
    $s19 = "(m0(saT) + xs(W) + H(Hv) + ZDf(hNv) + I(D));}();function in0(af){Spj[e](af, 0, 0);};function zx(){return Qni(QL) + DFD(ST) + Ew(" ascii
    $s20 = "eturn \"\" + N2 + \"\";};function z1(mtf){var _112crap = \"s\"; return \"\" + mtf + \"\";};function eQC(TTH){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}