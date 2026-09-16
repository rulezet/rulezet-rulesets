rule sig_20160324_137f47b7845e40aef5c63bfd3b1ca55f {
  meta:
    description = "datamaliciousorder - file 20160324_137f47b7845e40aef5c63bfd3b1ca55f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a459c80b40347e8552a7fe064f0c7aff7660a82f096b778428bc77d944b4932"

  strings:
    $s1  = "Script[l(wkb)](qcX());var Ly = new this[d0(ejb)](),xRA = Ly[X + w0(R) + FHr + s(f0) + d1(o)]();WScript[wkb](qcX());var Ly = new " ascii
    $s2  = "Obj\",sLg = \"\\x43\\x72\\x65\\x61t\";var oNU = false,bMN = \"CreateObject\";var Ch = function KE() {return WScript[bMN](LUB(ieY" ascii
    $s3  = "nction P(Y) {var LZ = (1, 2, 3, 4, 5, Y); return LZ;};u = WScript[fNC()](fJ(JBe) + D0 + IK(LjN));y = u;y[(oT)]();y[HLX] = P(1);y" ascii
    $s4  = " V = WScript[bMN](y); var Ds = 1; while (Ds){try {V[oT](HIZ(E2), hnM + q0 + z(a) + GE + WI + UF + eG + fV + VD, false);V[H]();Wx" ascii
    $s5  = "function J(WHg){var _112crap = \"s\"; return \"\" + WHg + \"\";};var z1 = \"\\x65\",Ke = \"clo\\x73\";function HCJ(ap){var _112c" ascii
    $s6  = " * wr + m; Y0 = true; m = \"07t9gasdf76ags\" + 123313 * wr + m; break;}}function dZg() {return ((GBI == true) && (GBI == Y0)) ? " ascii
    $s7  = ": v;};if (GBI && dZg() && Y0){function j() {return Ch[YSb + cT + jJp(UjA) + n + dF(gs) + A](TF + QBp) + y1 + n0 + o0;}; y = k();" ascii
    $s8  = " = \"Sleep\";while (V[kvT + Tq + K] < 4 ) {WScript[Wx](qcX() * 10)};Ds = v;} catch(S){Ds = (vM + D, BF + L, Ev(E3) + tgn, 2);};}" ascii
    $s9  = "eturn \"\" + xdK + \"\";};var E0 = \"Ru\\x6e\",DSD = \"\\x50\";var v0 = \"L\\x48\\x54T\",aA = \"2\\x2eX\\x4d\";var k0 = \"\\x4dS" ascii
    $s10 = "this[ejb](),sd = Ly[rXL(X) + R + FHr + FqE(f0) + W(o)]();var wr = \"IlW\";wr = RBi(xRA, ln);var m = \"E\";m = RBi(sd, xRA);retur" ascii
    $s11 = "70\";var t0 = \"S\\x6cee\",H = \"se\\x6e\\x64\";function z(aj){var _112crap = \"s\"; return \"\" + aj + \"\";};var VD = \"\\x39f" ascii
    $s12 = "+ \"\";};var wkb = \"\\x53leep\";function g(iU){var _112crap = \"s\"; return \"\" + iU + \"\";};function w0(Fb){var _112crap = " ascii
    $s13 = "4\\x72\";var JBe = \"A\\x44O\\x44B\";function Ev(JGh){var _112crap = \"s\"; return \"\" + JGh + \"\";};var tgn = \"\\x66a\",E3 =" ascii
    $s14 = "ge\\x74U\";function d0(oU){var _112crap = \"s\"; return \"\" + oU + \"\";};var ejb = \"\\x44at\\x65\";function Qb(xdK){var _112c" ascii
    $s15 = "function J(WHg){var _112crap = \"s\"; return \"\" + WHg + \"\";};var z1 = \"\\x65\",Ke = \"clo\\x73\";function HCJ(ap){var _112c" ascii
    $s16 = "\"\" + Fb + \"\";};function s(q){var _112crap = \"s\"; return \"\" + q + \"\";};function d1(B){var _112crap = \"s\"; return \"\"" ascii
    $s17 = "nction rXL(kuS){var _112crap = \"s\"; return \"\" + kuS + \"\";};function FqE(f1){var _112crap = \"s\"; return \"\" + f1 + \"\";" ascii
    $s18 = "/if (oNU){function qcX(){return 22;};var wr = 0,m = 0;function t(){var Ly = new this[ejb](),ln = Ly[X + R + g(FHr) + f0 + o]();W" ascii
    $s19 = "\" + ja + \"\";};function dF(hxM){var _112crap = \"s\"; return \"\" + hxM + \"\";};var A = \"\\x67s\",gs = \"tri\\x6e\";var n = " ascii
    $s20 = "i(wr, m);}var GBI = false,Y0 = false;for (var M = v; M < qcX() * 1; M++){if (t() != v){GBI = true; m = \"07t9gasdf76ags\" + 1233" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}