rule sig_20160323_cbc1c38e92dc6ec6dca73dc4da552e1f {
  meta:
    description = "datamaliciousorder - file 20160323_cbc1c38e92dc6ec6dca73dc4da552e1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9664067417deda0afc22443e40eef9f9084e000a2ad2ffb6732331d1498244e8"

  strings:
    $s1  = "function Y0(QHZ){var _112crap = \"s\"; return \"\" + QHZ + \"\";};var Th = \"se\",tz = \"clo\";function BPa(ams){var _112crap = " ascii
    $s2  = "G){var _112crap = \"s\"; return \"\" + G + \"\";};function u0(S1){var _112crap = \"s\"; return \"\" + S1 + \"\";};var nan = \"J." ascii
    $s3  = "),cu = \"eOb\\x6a\";var j = \"t\",vqd = \"Crea\";var QxH = false,Elb = function qdv() {return WScript[lb(vqd) + q(j) + cu + n + " ascii
    $s4  = "Z(p2) + YAv(iO) + P1(x) + yY(zk), false);Sd[cON(u1) + OC(a1)]();while (Sd[i2(Mh) + fMw + f0(ic)] < 4 ) {WScript[lS(m) + fKK(t)](" ascii
    $s5  = "FPY + y0(spP)](),Sn = JVW[hh(NhX) + X(O) + iUC(XrL) + ym(HMi) + hFy]();WScript[s1(m) + P0(t)](tZK());var JVW = new this[FPY + TI" ascii
    $s6  = " {var gS = (1, 2, 3, 4, 5, bZ); return gS;};hAf = (oV) ? 14134 : 414234;SdV = WScript[i()](AqB(Xwh) + Hx(aJ) + c1(F1));bwH = SdV" ascii
    $s7  = "M(spP)](),vu = JVW[bsV(NhX) + HVS(O) + n2(XrL) + ylP(HMi) + A0(hFy)]();WScript[m + wL(t)](tZK());var JVW = new this[z(FPY) + spP" ascii
    $s8  = " y + a(p);};function Rg(Z, za){return Z - za;};function i(){return dWm(vqd) + E(j) + o(cu) + BZ(n) + qAs(K0);};/*@cc_on  @if (@_" ascii
    $s9  = "J = \"l\\x74.c\";var jG = \"co\\x6e\\x73u\",N1 = \"/vl-\";var IU = \"/\",Px = \"\\x74p:\";var HDo = \"\\x68t\";function icr(oS){" ascii
    $s10 = "\\x79e\\x65y\";var RZ = \"\\x67\\x72\\x6fV\\x36\";function GB(v){var _112crap = \"s\"; return \"\" + v + \"\";};function K3(h1){" ascii
    $s11 = "ML\\x48\";var Hbl = \"\\x32.\",YCG = \"\\x4dSX\\x4dL\";function IGE(F){var _112crap = \"s\"; return \"\" + F + \"\";};function B" ascii
    $s12 = "function Y0(QHZ){var _112crap = \"s\"; return \"\" + QHZ + \"\";};var Th = \"se\",tz = \"clo\";function BPa(ams){var _112crap = " ascii
    $s13 = "(TA(T) + XgM + n0 + Ty + K2(wy));}();function BKd(ZfN){Elb[IGE(VE) + B(HxJ)](ZfN, 0, 0);};function W(){return P(YCG) + tZ(Hbl) +" ascii
    $s14 = "V){var _112crap = \"s\"; return \"\" + V + \"\";};function f0(tnd){var _112crap = \"s\"; return \"\" + tnd + \"\";};var ic = \"" ascii
    $s15 = "wH); var Wq = true; while (Wq){try {Sd[qvN(Mk) + dRg(B2)](icr(Pdm) + F0(CI), nWV(HDo) + xxB(Px) + IU + S3(N1) + jG + t0(ulJ) + n" ascii
    $s16 = " \"ty\";var VS = \"open\";function AqB(Hkg){var _112crap = \"s\"; return \"\" + Hkg + \"\";};function Hx(vIw){var _112crap = \"s" ascii
    $s17 = "ak){var _112crap = \"s\"; return \"\" + ak + \"\";};function a(XGH){var _112crap = \"s\"; return \"\" + XGH + \"\";};var p = \"T" ascii
    $s18 = "s\"; return \"\" + RMj + \"\";};function P0(gF){var _112crap = \"s\"; return \"\" + gF + \"\";};function wL(fnQ){var _112crap = " ascii
    $s19 = "2crap = \"s\"; return \"\" + h0 + \"\";};function EmH(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};function Er(sO){var _1" ascii
    $s20 = " \"e\";var zj = \"R\";function wz(n4){var _112crap = \"s\"; return \"\" + n4 + \"\";};var tX = \"it\\x65\",biL = \"w\\x72\";var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}