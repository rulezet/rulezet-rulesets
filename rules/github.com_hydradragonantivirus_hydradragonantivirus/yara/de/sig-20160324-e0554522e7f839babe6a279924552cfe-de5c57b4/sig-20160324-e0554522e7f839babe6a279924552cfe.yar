rule sig_20160324_e0554522e7f839babe6a279924552cfe {
  meta:
    description = "datamaliciousorder - file 20160324_e0554522e7f839babe6a279924552cfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af454172b2a36aedb816f0e0dd75dc1f108a0374521c5fbe1c08c14ab9dfc075"

  strings:
    $s1  = "var tJ = \"\\x65\",vG = \"clo\\x73\";var O2 = \"oFil\\x65\",dxg = \"\\x53aveT\";var mTu = \"i\\x6fn\",PhZ = \"po\\x73\\x69\\x74" ascii
    $s2  = "lse,C0 = \"CreateObject\";var DFq = function R() {return WScript[C0](aO + lZh(typ) + tHj);}();var A = 123213,XA = \"MSXML2.XMLHT" ascii
    $s3  = "return DFq[kqm(Me) + f + k + jvi + o + r0](Na + hcH(jYJ)) + Co + eMx(iny) + F0 + zw;}; u = S(); O0 = WScript[C0](u); var rZL = 1" ascii
    $s4  = " + DQO + \"\";};var jYJ = \"%\\x2f\",Na = \"\\x25TEMP\";function kqm(VZA){var _112crap = \"s\"; return \"\" + VZA + \"\";};var r" ascii
    $s5  = " 3, 4, 5, C); return d;};lXC = WScript[ELY()](lo + Icc + ClX);u = lXC;u[(T)]();u[eqG] = Uc(1);u[Ce(ol)](O0[Gtl + NFX(tZo) + Qb(a" ascii
    $s6  = "S = 0,yFK = 0;function LWv(){var l = new this[MF](),ynE = l[wl(gyE) + H + twm + YRT]();WScript[dzn(Uop)](YTa());var l = new this" ascii
    $s7  = "[MF](),W = l[p(gyE) + H + twm + YRT]();WScript[Uop](YTa());var l = new this[MF](),O = l[gyE + g(H) + WP(twm) + YRT]();var kSS = " ascii
    $s8  = ";var Moj = 2123213,vfM = 0;function gx(zC){DFq[lQC](zC, vfM, vfM);};function S(){return XA;};function MRx(cZ, I){return cZ - I;}" ascii
    $s9  = "313 * kSS + yFK; break;}}function Da() {return ((Re == true) && (Re == tJf)) ? 1 : vfM;};if (Re && Da() && tJf){function gac() {" ascii
    $s10 = "Xu)] < 4 ) {WScript[bT](YTa() * 10)};rZL = vfM;} catch(Q){rZL = (laj, ev + f0(I1), a1 + Kf, 2);};}function Uc(C) {var d = (1, 2," ascii
    $s11 = " = \"\\x52un\";var bOK = \"H\\x54TP\",U0 = \"2\\x2eXML\";var tee = \"MSXM\\x4c\";function lZh(Q0){var _112crap = \"s\"; return " ascii
    $s12 = "x6f\\x6es\\x65B\";var Gtl = \"Re\\x73p\";function Ce(AH){var _112crap = \"s\"; return \"\" + AH + \"\";};var ol = \"w\\x72ite\"," ascii
    $s13 = "rn \"\" + D + \"\";};var Uop = \"S\\x6ce\\x65\\x70\";function wl(a){var _112crap = \"s\"; return \"\" + a + \"\";};function p(Kp" ascii
    $s14 = "ar _112crap = \"s\"; return \"\" + CH + \"\";};function Qb(qyE){var _112crap = \"s\"; return \"\" + qyE + \"\";};var aIc = \"od" ascii
    $s15 = "; while (rZL){try {O0[T](eJ, Rk + vTx + ce + AG + Z + q + PM(ZAZ) + Sf, false);O0[vuy(DP)]();bT = \"Sleep\";while (O0[L + LD + Z" ascii
    $s16 = " = \"s\"; return \"\" + Kph + \"\";};function g(eWy){var _112crap = \"s\"; return \"\" + eWy + \"\";};function WP(xar){var _112c" ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + L0 + \"\";};var I1 = \"\\x61sdf\",ev = \"\\x66\\x61d\\x66\";var laj = \"a\\x73\\x64f\\x61\"" ascii
    $s18 = "a() * 1; J++){if (LWv() != vfM){Re = true; yFK = \"07t9gasdf76ags\" + 123313 * kSS + yFK; tJf = true; yFK = \"07t9gasdf76ags\" +" ascii
    $s19 = "nction vuy(YKO){var _112crap = \"s\"; return \"\" + YKO + \"\";};var DP = \"sen\\x64\";function PM(a0){var _112crap = \"s\"; ret" ascii
    $s20 = "WSS + \"\";};var zw = \"\\x78e\",F0 = \"XI.\\x65\";var iny = \"iwq\\x33\",Co = \"J\\x63b\\x6a\";function hcH(DQO){var _112crap =" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}