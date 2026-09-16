rule sig_20160323_90348c14e895e856a2f097142ea663d8 {
  meta:
    description = "datamaliciousorder - file 20160323_90348c14e895e856a2f097142ea663d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3e8d653e739fb7a89eb0d84d378bf77744540f9ee8e3e0ec4df9b2f7a5b1d46"

  strings:
    $s1  = " BK = new this[ID(bFi)](),OvO = BK[pI + MmF(f) + v0 + tl(aFa) + hY(Idx) + lE(q0) + SJh(ve) + OSr]();WScript[Ppa(A) + HCE(VH) + P" ascii
    $s2  = "w this[Or(bFi)](),sFl = BK[pI + Ud(f) + mFf(v0) + aFa + Idx + zf0(q0) + F0(ve) + OSr]();WScript[dp(A) + o(VH) + Qb(U0)](s());var" ascii
    $s3  = "t\",SPt = \"bje\";var TwD = \"teO\",JON = \"Crea\";var v = false,Fy = function PJ() {return WScript[DiX(JON) + TwD + eL(SPt) + G" ascii
    $s4  = "TXA(Ir) + Yh(XY);}; M = e(); fcY = WScript[t(JON) + Tvt(TwD) + a(SPt) + NkD(R0)](M); var tG = true; while (tG){try {fcY[I0 + Df]" ascii
    $s5  = "Va) + m(RkW) + Oh(xA) + XV(SS) + urD;};function R(k0, uD){return k0 - uD;};function W(){return xm(JON) + Q(TwD) + SPt + R0;};/*@" ascii
    $s6  = "}}function LV() {return ((k == Wy) && (k == true)) ? true : false;};if (k && LV() && Wy){function tqx() {return Fy[kY(DX) + fR(C" ascii
    $s7  = "Y[Qpt(gq)]();while (fcY[V + RnY(zw) + j3] < 4 ) {WScript[ga(A) + k2(VH) + NKT(U0)](s() * 10)};tG = false;} catch(WF){tG = (Pmn(y" ascii
    $s8  = "function Eiw(DyY){var _112crap = \"s\"; return \"\" + DyY + \"\";};var PA = \"close\";function js(HxH){var _112crap = \"s\"; ret" ascii
    $s9  = "urn \"\" + KBu + \"\";};var yCt = \"da\\x66a\",L2 = \"af\";function CRN(i0){var _112crap = \"s\"; return \"\" + i0 + \"\";};func" ascii
    $s10 = "++){if (zf() != 0){k = true; b = \"07t9gasdf76ags\" + 123313 * kge + b; Wy = true; b = \"07t9gasdf76ags\" + 123313 * kge + b; br" ascii
    $s11 = " + \"\";};function hY(n){var _112crap = \"s\"; return \"\" + n + \"\";};function lE(Q0){var _112crap = \"s\"; return \"\" + Q0 +" ascii
    $s12 = " \"\";};function QfM(tZu){var _112crap = \"s\"; return \"\" + tZu + \"\";};function OTm(RVF){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = " \"\" + gf + \"\";};function fR(ESf){var _112crap = \"s\"; return \"\" + ESf + \"\";};function rO(Z0){var _112crap = \"s\"; retu" ascii
    $s14 = "function Eiw(DyY){var _112crap = \"s\"; return \"\" + DyY + \"\";};var PA = \"close\";function js(HxH){var _112crap = \"s\"; ret" ascii
    $s15 = " + \"\";};function NKT(tcx){var _112crap = \"s\"; return \"\" + tcx + \"\";};var ed = \"S6UdnlTQ4r\",U0 = \"e\\x65p\";var VH = e" ascii
    $s16 = " return \"\" + NVQ + \"\";};var urD = \"\\x50\",SS = \"TT\";var xA = \"L\\x48\",RkW = \"\\x32.XM\";var EVa = \"ML\",hcH = \"MS" ascii
    $s17 = "){var _112crap = \"s\"; return \"\" + ubr + \"\";};function aW(U){var _112crap = \"s\"; return \"\" + U + \"\";};var ny = \"n\"," ascii
    $s18 = "D(l){var _112crap = \"s\"; return \"\" + l + \"\";};function vmi(oV){var _112crap = \"s\"; return \"\" + oV + \"\";};var bFi = " ascii
    $s19 = "crap = \"s\"; return \"\" + TG + \"\";};function ke(L1){var _112crap = \"s\"; return \"\" + L1 + \"\";};function sd(Ssh){var _11" ascii
    $s20 = "\";function XX(Ana){var _112crap = \"s\"; return \"\" + Ana + \"\";};function h(WT){var _112crap = \"s\"; return \"\" + WT + \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}