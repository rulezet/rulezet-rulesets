rule sig_20160323_ffd0c358a6bfd7d04109a1d74f7928b9 {
  meta:
    description = "datamaliciousorder - file 20160323_ffd0c358a6bfd7d04109a1d74f7928b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "255d0713904e7495d05ddf042759232ccb908bef4066f461ad67195875be4d36"

  strings:
    $s1  = "function dqY(xu){var _112crap = \"s\"; return \"\" + xu + \"\";};var t1 = \"o\\x73e\",Y2 = \"c\\x6c\";function MKs(UJz){var _112" ascii
    $s2  = "\"+\"A\"+\"\\x74\"+\"\"](3),Mc = false;var L = function z() {return WScript[jLH(Th) + ziF + cR(Fvp) + nSP](kpS + Z0(YF) + l0(mHF" ascii
    $s3  = ") + nl(eh) + p(jqY) + ZQx(VrK) + vt + PVL(lB)]();WScript[H(Fw)](t());var WTX = new this[xHr(N) + N0(IGR)](),z0 = WTX[pf + cyw(Py" ascii
    $s4  = "(SX) + QI) + vCi(E1) + LEw(F2) + E2 + zto;}; bZM = n(); cE = WScript[Th + ziF + YHM(Fvp) + OFm(nSP)](bZM); var QJP = true; while" ascii
    $s5  = "(eh) + Jzn(jqY) + xd(VrK) + Wup(vt) + UM(lB)]();WScript[vM(Fw)](t());var WTX = new this[N + XTV(IGR)](),e = WTX[gJe(pf) + edH(Py" ascii
    $s6  = " + mRu; Yz = true; mRu = \"07t9gasdf76ags\" + 123313 * TK0 + mRu; break;}}function d() {return ((i == Yz) && (i == true)) ? true" ascii
    $s7  = "s\"; return \"\" + kYS + \"\";};var ez = \"e\",l3 = \"a\\x74\";var pjx = \"\\x79st\",Vo = \"read\";function F3(IaJ){var _112crap" ascii
    $s8  = " false;};if (i && d() && Yz){function q() {return L[ZzW + jxE(uyB) + I1(o) + t0(E0) + DHA(ro) + IY(RvM) + GO(Y)](i0 + rZ(D0) + J" ascii
    $s9  = ")]();while (cE[jCa(Vo) + xBd(pjx) + g0(l3) + UzR(ez)] < 4 ) {WScript[Fw](t() * 10)};QJP = false;} catch(S){QJP = (b1(j0), k(E3) " ascii
    $s10 = "0 + \"\";};function d2(P){var _112crap = \"s\"; return \"\" + P + \"\";};var gFr = \"kCXFC\",lB = \"s\";var vt = \"\\x63\\x6fnd" ascii
    $s11 = "+ \"\";};function DVt(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};var gy = \"\\x70e\",Jxu = \"\\x74y\";var gL = \"\\x65" ascii
    $s12 = "S(sUG){var _112crap = \"s\"; return \"\" + sUG + \"\";};function U0(dGP){var _112crap = \"s\"; return \"\" + dGP + \"\";};functi" ascii
    $s13 = "var i = false,Yz = false;for (var QKQ = 0; QKQ < t() * 1; QKQ++){if (PSQ() != 0){i = true; mRu = \"07t9gasdf76ags\" + 123313 * T" ascii
    $s14 = "s\"; return \"\" + fh + \"\";};var d0 = \"dXOCIoY\",nSP = \"t\";var Fvp = \"\\x4fbj\\x65c\",ziF = \"\\x72\\x65\\x61\\x74e\";var " ascii
    $s15 = "H){var _112crap = \"s\"; return \"\" + TH + \"\";};function nnI(U1){var _112crap = \"s\"; return \"\" + U1 + \"\";};var evX = \"" ascii
    $s16 = "return \"\" + b2 + \"\";};function x0(pUy){var _112crap = \"s\"; return \"\" + pUy + \"\";};var V = \"ornkt\",A2 = \"dy\";var V0" ascii
    $s17 = "f (Mc){function t(){return 22;};var TK0 = 0,mRu = 0;function PSQ(){var WTX = new this[N + ORQ(IGR)](),m = WTX[pf + wQu(Py) + tqJ" ascii
    $s18 = "; return \"\" + ouj + \"\";};function sR(sEE){var _112crap = \"s\"; return \"\" + sEE + \"\";};var sEv = \"a\\x66\\x61\",PN = \"" ascii
    $s19 = "ar _112crap = \"s\"; return \"\" + D + \"\";};function ZQx(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};function PVL(XY){" ascii
    $s20 = "){var _112crap = \"s\"; return \"\" + JVR + \"\";};var Y1 = \"f\",a1 = \"s\\x64\";var E3 = \"\\x66adfa\";function b1(Z1){var _11" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}