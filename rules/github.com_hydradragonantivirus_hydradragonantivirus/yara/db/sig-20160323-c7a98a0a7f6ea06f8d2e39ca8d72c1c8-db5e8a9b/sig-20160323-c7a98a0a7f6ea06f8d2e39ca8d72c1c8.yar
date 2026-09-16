rule sig_20160323_c7a98a0a7f6ea06f8d2e39ca8d72c1c8 {
  meta:
    description = "datamaliciousorder - file 20160323_c7a98a0a7f6ea06f8d2e39ca8d72c1c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8539a99018c677482dfe0aeb0491b8114c299c1c3331611636e8919cf79f122"

  strings:
    $s1  = "function zmp(W4){var _112crap = \"s\"; return \"\" + W4 + \"\";};var rRX = \"se\",dPF = \"\\x63\\x6co\";function MEr(UOJ){var _1" ascii
    $s2  = "W(MKU) + jPf(Wtc) + k(g0) + YDZ(ZG)]();WScript[wG(By) + hpj(eJS)](aL());var Ew = new this[xU + Z](),EwT = Ew[v0(vK) + q0 + jy(Fz" ascii
    $s3  = ") + W0(v) + JiR(YIe) + Ke(MKU) + Wtc + g0 + ug(ZG)]();WScript[By + Kh(eJS)](aL());var Ew = new this[n1(xU) + C0(Z)](),lS = Ew[vK" ascii
    $s4  = "function BFY() {return WScript[NEg(ih) + hF + JAE(mgf) + dH(H) + aM(q)](VMK + Nce(hi) + blW + PBS + z(tRI));}();function vR(MPC)" ascii
    $s5  = "\\x63\"+\"\"+\"\\x68\"+\"arAt\"](4);var cdk = \"%TE\";function Eg(T){var _112crap = \"s\"; return \"\" + T + \"\";};function L2(" ascii
    $s6  = "crap = \"s\"; return \"\" + m + \"\";};var a = \"6RFOlNmm\",tRI = a[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](4);var PBS = \"She" ascii
    $s7  = "\"\\x54CMi\",v1 = \"getU\";var sV = \"e\",LVQ = \"D\\x61t\";function wG(W1){var _112crap = \"s\"; return \"\" + W1 + \"\";};func" ascii
    $s8  = "D + \"\";};var qF = \"nLXsd\",unX = \"\\x73d\\x66\";var Vg = \"\\x66a\",zi = qF[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](4);var z" ascii
    $s9  = "ion f(v4){var _112crap = \"s\"; return \"\" + v4 + \"\";};var fi = \"ngkbia5x\",y1 = fi[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](" ascii
    $s10 = "Ln[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](3);function DwU(L3){var _112crap = \"s\"; return \"\" + L3 + \"\";};var gM = \"GE\\x5" ascii
    $s11 = "s\"; return \"\" + g + \"\";};var sss = \"IPZW80b\",cvy = sss[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](1);var fgz = \"\\x4dL\\x48" ascii
    $s12 = "12crap = \"s\"; return \"\" + ewJ + \"\";};var d1 = \"t\\x79p\\x65\",OhM = \"5UGn7\";var dhl = OhM[\"\"+\"\\x63\"+\"\"+\"\\x68\"" ascii
    $s13 = "{zbn[uJu](MPC, 0, 0);};function TNc(){return UC(y) + j0 + qOC + qP(fgz) + tV(cvy);};function A(Y, Nn){return Y - Nn;};function o" ascii
    $s14 = ") && (gzg == true)) ? true : false;};if (gzg && HAK() && rq){function J() {return zbn[edO + Eg(kj) + L2(l) + gKi(Yx) + KbO(d) + " ascii
    $s15 = "(y1), true);};}function yg(C) {var yNV = (1, 2, 3, 4, 5, C); return yNV;};OVx = (gzg) ? 14134 : 414234;V = WScript[o()](Po(Q1) +" ascii
    $s16 = " \"0Jor\",tUF = \"\\x63\\x74\";var x0 = \"eObje\",zCW = \"\\x65at\";var n0 = I[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](3),HmE = " ascii
    $s17 = " \"\";};function ao(V1){var _112crap = \"s\"; return \"\" + V1 + \"\";};function Ij(W2){var _112crap = \"s\"; return \"\" + W2 +" ascii
    $s18 = "q = \"\\x6d\",w0 = \"\\x72\\x65a\";var j2 = \"B\\x2eSt\",Q1 = \"\\x41\\x44OD\";function PQ(EA){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "asdf76ags\" + 123313 * OVx + QK; rq = true; QK = \"07t9gasdf76ags\" + 123313 * OVx + QK; break;}}function HAK() {return ((gzg ==" ascii
    $s20 = "\" + SQ + \"\";};function v0(L0){var _112crap = \"s\"; return \"\" + L0 + \"\";};function jy(WN){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}