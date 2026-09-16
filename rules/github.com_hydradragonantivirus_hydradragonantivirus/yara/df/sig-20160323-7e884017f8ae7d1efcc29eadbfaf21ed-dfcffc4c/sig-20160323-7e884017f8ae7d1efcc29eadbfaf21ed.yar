rule sig_20160323_7e884017f8ae7d1efcc29eadbfaf21ed {
  meta:
    description = "datamaliciousorder - file 20160323_7e884017f8ae7d1efcc29eadbfaf21ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75bf82a05890e1b093ee5a9f61571201b75e5168ce3db4eb3eaebf832cfe0a95"

  strings:
    $s1  = "function wVq(N2){var _112crap = \"s\"; return \"\" + N2 + \"\";};function V2(Du){var _112crap = \"s\"; return \"\" + Du + \"\";}" ascii
    $s2  = "x65c\",bC = \"eate\";var C = \"Cr\",uB = false;var QQ = function ae() {return WScript[x(C) + bC + Ah + nE(wrS)](wBh(pQz) + n + B" ascii
    $s3  = " + XIK + ULI + LuP(Rnv);}; g = U(); L = WScript[C + EE(bC) + Ni(Ah) + U0(wrS)](g); var me = true; while (me){try {L[Z0 + tu](idu" ascii
    $s4  = "+ wpn + JD]();WScript[VTV(V0) + cKJ(dC)](r());var GDw = new this[G0 + kDe(Hj)](),p = GDw[s1(aDF) + EdK + Ho(h0) + npF(Yof) + Txz" ascii
    $s5  = "(H) + Leq(wpn) + l(JD)]();WScript[V0 + q(dC)](r());var GDw = new this[f0(G0) + UUa(Hj)](),HpD = GDw[u(aDF) + EdK + om(h0) + H0(Y" ascii
    $s6  = "));}();function HPW(QL){QQ[Ei(gJ)](QL, 0, 0);};function U(){return V(O1) + R0 + N(nW) + S0(r0);};function Zr(e, vTf){return e - " ascii
    $s7  = "= \"M\\x53\\x58\\x4d\";function Ei(cQe){var _112crap = \"s\"; return \"\" + cQe + \"\";};var gJ = \"Run\";function wBh(O0){var _" ascii
    $s8  = "Zo && s() && Ju){function S() {return QQ[E1(xlY) + EML + B + xK(qB) + l1(E0) + N0 + rgc(Zp) + MY(p0) + qVv(T)](Ih + H1) + iY(Kx)" ascii
    $s9  = " MJA = \"07t9gasdf76ags\" + 123313 * IwY + MJA; break;}}function s() {return ((SZo == Ju) && (SZo == true)) ? true : false;};if " ascii
    $s10 = ",RQ = \"vl\";var X = \"tp:\\x2f/\",EG = y0[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](1);var QX = \"\\x68\";function " ascii
    $s11 = "V1) + ZUv(o) + ny(wk) + b(qd)] < 4 ) {WScript[V0 + Zzw(dC)](r() * 10)};me = false;} catch(f){me = (KN + cD(lm) + BuW(ve), v1(f1)" ascii
    $s12 = "+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](2);function Q2(VK){var _112crap = \"s\"; return \"\" + VK + \"\";};var cPn = \"" ascii
    $s13 = "2crap = \"s\"; return \"\" + vaO + \"\";};function f0(hr){var _112crap = \"s\"; return \"\" + hr + \"\";};function UUa(s0){var _" ascii
    $s14 = "unction T0(mXQ){var _112crap = \"s\"; return \"\" + mXQ + \"\";};function Z2(cQ){var _112crap = \"s\"; return \"\" + cQ + \"\";}" ascii
    $s15 = "112crap = \"s\"; return \"\" + RS + \"\";};function LuP(kXw){var _112crap = \"s\"; return \"\" + kXw + \"\";};var n0 = \"tDFaPen" ascii
    $s16 = ";function BuW(XRl){var _112crap = \"s\"; return \"\" + XRl + \"\";};var B0 = \"DaenzV\",Dxx = \"tjXbaZkXz\";var ve = Dxx[\"ch\"+" ascii
    $s17 = " = \"Sa\\x76\";function G2(pjp){var _112crap = \"s\"; return \"\" + pjp + \"\";};var Vxf = \"tion\",lQ = \"\\x70\\x6fsi\";functi" ascii
    $s18 = "pQz = \"\\x57S\\x63\\x72i\";function x(HEr){var _112crap = \"s\"; return \"\" + HEr + \"\";};function nE(R){var _112crap = \"s\"" ascii
    $s19 = "; return \"\" + O0 + \"\";};function BtQ(QPv){var _112crap = \"s\"; return \"\" + QPv + \"\";};var aB = \"el\\x6c\",n = \"\\x70t" ascii
    $s20 = "\"; return \"\" + s0 + \"\";};var Ya = \"re\",Hj = Ya[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](1);var G0 = \"Dat\"," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}