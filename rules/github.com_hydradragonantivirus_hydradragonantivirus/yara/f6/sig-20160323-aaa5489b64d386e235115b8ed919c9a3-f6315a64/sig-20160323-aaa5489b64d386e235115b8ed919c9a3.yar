rule sig_20160323_aaa5489b64d386e235115b8ed919c9a3 {
  meta:
    description = "datamaliciousorder - file 20160323_aaa5489b64d386e235115b8ed919c9a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20a5013b46515b3d8dcb2a781bc8848a538a25f6d06e5a9c06de20212bf93b55"

  strings:
    $s1  = " m(Amf)](),w = SIt[P + X + jY(Rgd) + V(mk) + pHn(WP)]();WScript[ArI(QY) + mf(b1) + xx(dMH)](f());var SIt = new this[ymf(v0) + jD" ascii
    $s2  = "function za(HRT){var _112crap = \"s\"; return \"\" + HRT + \"\";};var zmf = \"close\";function k0(X2){var _112crap = \"s\"; retu" ascii
    $s3  = "dbd[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](3),y = \"C\\x72e\";var Wl = false,KiY = function G() {return WScript[T" ascii
    $s4  = "ew this[v0 + Amf](),hW = SIt[P + X + RE(Rgd) + lLl(mk) + iUw(WP)]();WScript[QY + b1 + F0(dMH)](f());var SIt = new this[EoV(v0) +" ascii
    $s5  = "AGP) + b2(IA) + oQ, true);};}function Or(oN) {var d = (1, 2, 3, 4, 5, oN); return d;};fr = (Czw) ? 14134 : 414234;ZQU = WScript[" ascii
    $s6  = "bG = \"tt\";var Atj = \"h\";function n1(cu){var _112crap = \"s\"; return \"\" + cu + \"\";};var yqX = \"GET\";function QW(QaE){v" ascii
    $s7  = "on\\x64\";var Rgd = \"i\\x6clis\",X = \"CM\";var P = \"getU\\x54\";function EoV(YY){var _112crap = \"s\"; return \"\" + YY + \"" ascii
    $s8  = ") + aeu(GyV) + eMH(sW);};function XXa(Gp, N){return Gp - N;};function B(){return K(y) + Rj(Wx) + M(Sk) + VT(Om) + XW(ih);};/*@cc" ascii
    $s9  = " + lM; H = true; lM = \"07t9gasdf76ags\" + 123313 * fr + lM; break;}}function k() {return ((Czw == H) && (Czw == true)) ? true :" ascii
    $s10 = "alse;};if (Czw && k() && H){function pKK() {return KiY[E(X1) + ny(Fl) + sd(qL) + a(hwr) + LB + pC(bC) + mE(h1) + mk0(kAW)](bws +" ascii
    $s11 = " Q2(XY)] < 4 ) {WScript[fHL(QY) + b1 + bHr(dMH)](f() * 10)};vN = false;} catch(Odp){vN = (U0(S1), rY(ijJ) + i1(Tc) + wC(x0), a1(" ascii
    $s12 = "\\x61\\x73\\x64\",ijJ = \"f\\x61\";function U0(vpf){var _112crap = \"s\"; return \"\" + vpf + \"\";};var S1 = \"as\\x64fa\",LzI " ascii
    $s13 = "r y1 = \"\\x6fdy\",Sj = \"\\x65\\x42\";var Y = \"\\x73pons\",Z0 = \"Re\";function uWR(gh){var _112crap = \"s\"; return \"\" + gh" ascii
    $s14 = "tion amT(J0){var _112crap = \"s\"; return \"\" + J0 + \"\";};var dbd = \"lEOajUdx4\",ih = \"ct\";var Om = \"\\x4fb\\x6ae\",Sk = " ascii
    $s15 = "12crap = \"s\"; return \"\" + Dg + \"\";};var Ggo = \"eyVTX\",Amf = Ggo[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](0)" ascii
    $s16 = "r V3 = \"\\x6c\\x65\",F2 = \"F\\x69\";var V2 = \"e\\x54o\",f0 = \"Sav\";function pLf(o0){var _112crap = \"s\"; return \"\" + o0 " ascii
    $s17 = "return \"\" + I1 + \"\";};var rm = \"n8m2OcYuZJ\",ipW = \"Yeluyq\";var SnF = \"a\\x6d\",D0 = ipW[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"" ascii
    $s18 = " \"\";};function V(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";};function pHn(R0){var _112crap = \"s\"; return \"\" + R0 +" ascii
    $s19 = "function za(HRT){var _112crap = \"s\"; return \"\" + HRT + \"\";};var zmf = \"close\";function k0(X2){var _112crap = \"s\"; retu" ascii
    $s20 = "(bep){var _112crap = \"s\"; return \"\" + bep + \"\";};function J(u){var _112crap = \"s\"; return \"\" + u + \"\";};function K(b" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}