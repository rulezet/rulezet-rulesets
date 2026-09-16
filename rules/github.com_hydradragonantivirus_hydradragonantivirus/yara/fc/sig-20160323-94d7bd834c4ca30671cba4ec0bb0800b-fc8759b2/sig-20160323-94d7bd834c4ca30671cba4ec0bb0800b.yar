rule sig_20160323_94d7bd834c4ca30671cba4ec0bb0800b {
  meta:
    description = "datamaliciousorder - file 20160323_94d7bd834c4ca30671cba4ec0bb0800b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11fe1a265f83cef87d7fde8cca280bf0f04b1bb898228c9f62b019baa29a5af3"

  strings:
    $s1  = " ssi = (1, 2, 3, 4, 5, X); return ssi;};v = (rv) ? 14134 : 414234;J = WScript[dOF()](y1 + ea + v1(rF) + f(lHv));oK = J;E = (ElN)" ascii
    $s2  = "){var L = new this[YT(KB) + HoM](),P = L[bAc(eYR) + y0(z1) + s + vx(B0) + bw(Yb) + du(Gr) + xQw(GBA)]();WScript[hPZ(z2)](DO());v" ascii
    $s3  = "ar L = new this[GB(KB) + ydv(HoM)](),wG = L[Hys(eYR) + z1 + HUW(s) + S0(B0) + p0(Yb) + Gr + AZY(GBA)]();WScript[z2](DO());var L " ascii
    $s4  = "on Pn() {return WScript[X0 + X1(HO) + o0](MI(vUd) + Rwl(D) + i + AF + y);}();function B(JEd){ddF[Pw(g)](JEd, 0, 0);};function NN" ascii
    $s5  = "e(wcN) + dD + pM + p1 + cvd(Y1), false);CP[v0(akg) + tb(ja)]();while (CP[qn(o1) + BdO + NN(qb) + Ey(Ov)] < 4 ) {WScript[z2](DO()" ascii
    $s6  = "H(){return p(krU) + RvZ(xQ) + fQ + S(UI) + VF(dRc);};function QD(k, L0){return k - L0;};function dOF(){return Sra(X0) + HO + kK(" ascii
    $s7  = " + \"\";};var Z = \"idky3sgU3a\",Ov = \"ta\\x74\\x65\";var qb = Z[\"cha\"+\"\\x72\"+\"At\"](5),BdO = \"y\";var o1 = \"read\";fun" ascii
    $s8  = "lN) && (rv == true)) ? true : false;};if (rv && d() && ElN){function rt() {return ddF[aMF(gA) + Fx(edl) + W + gK(Vz) + SB(G) + a" ascii
    $s9  = "function Zd(Y3){var _112crap = \"s\"; return \"\" + Y3 + \"\";};function BFu(qQg){var _112crap = \"s\"; return \"\" + qQg + \"\"" ascii
    $s10 = "\\x55TCM\",eYR = \"ge\\x74\";function YT(sFM){var _112crap = \"s\"; return \"\" + sFM + \"\";};function GB(Qov){var _112crap = " ascii
    $s11 = "\\x4e\";var Olz = \"Z4\";function P0(TM){var _112crap = \"s\"; return \"\" + TM + \"\";};var XFj = \"\\x25/\",dAD = \"%T\\x45\\x" ascii
    $s12 = "2crap = \"s\"; return \"\" + d0 + \"\";};function RvZ(ukG){var _112crap = \"s\"; return \"\" + ukG + \"\";};function S(oj){var _" ascii
    $s13 = "Rk){var _112crap = \"s\"; return \"\" + Rk + \"\";};function Rwl(Rrd){var _112crap = \"s\"; return \"\" + Rrd + \"\";};var WYW =" ascii
    $s14 = "Y + \"\";};function Sra(YU){var _112crap = \"s\"; return \"\" + YU + \"\";};function kK(qY){var _112crap = \"s\"; return \"\" + " ascii
    $s15 = "E = \"07t9gasdf76ags\" + 123313 * v + E; ElN = true; E = \"07t9gasdf76ags\" + 123313 * v + E; break;}}function d() {return ((rv " ascii
    $s16 = ",xQ = \"M\\x4c\\x32.\";var krU = \"\\x4d\\x53X\";function Pw(oT){var _112crap = \"s\"; return \"\" + oT + \"\";};var g = \"Ru\\x" ascii
    $s17 = "ar _112crap = \"s\"; return \"\" + Xo + \"\";};function NnB(r){var _112crap = \"s\"; return \"\" + r + \"\";};function e(x){var " ascii
    $s18 = " + \"\";};var HoM = \"te\",KB = \"Da\";var A = \"\\x74\",sy = \"c\";var DUq = \"O\\x62\\x6ae\",T = \"eate\";var jis = \"Cr\";fun" ascii
    $s19 = "var RC = \"a\\x76\",hNe = \"\\x53\";function S1(FIh){var _112crap = \"s\"; return \"\" + FIh + \"\";};function py(bof){var _112c" ascii
    $s20 = "s\"; return \"\" + x + \"\";};function cvd(RFT){var _112crap = \"s\"; return \"\" + RFT + \"\";};var up = \"KcvPhF5W3W\",Y1 = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}