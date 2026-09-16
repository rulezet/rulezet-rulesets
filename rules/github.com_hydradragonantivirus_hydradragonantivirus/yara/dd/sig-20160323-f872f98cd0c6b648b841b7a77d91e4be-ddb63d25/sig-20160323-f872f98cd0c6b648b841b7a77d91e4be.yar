rule sig_20160323_f872f98cd0c6b648b841b7a77d91e4be {
  meta:
    description = "datamaliciousorder - file 20160323_f872f98cd0c6b648b841b7a77d91e4be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf526cdf4833600646ade3133ff4da92c5996eca1879c594e84f4dcc1baa4d0"

  strings:
    $s1  = "function V(pd){var _112crap = \"s\"; return \"\" + pd + \"\";};var cct = \"c\\x6cose\";function ySZ(hH){var _112crap = \"s\"; re" ascii
    $s2  = " = new this[X1(o)](),UYg = Dww[X2(Z0) + ij(Cj) + T(VO) + Bp(xQa) + Fi(xvu) + Sd(r)]();WScript[m(C)](u());var Dww = new this[o]()" ascii
    $s3  = "nction XU(){var Dww = new this[s0(o)](),R = Dww[S(Z0) + icE(Cj) + WUR(VO) + UL(xQa) + k0(xvu) + dF(r)]();WScript[C](u());var Dww" ascii
    $s4  = " \"b\";var ej = \"/\\x2fa\",fSL = \"p:\";var Y = \"ht\\x74\";function RG(S3){var _112crap = \"s\"; return \"\" + S3 + \"\";};var" ascii
    $s5  = "on Lo() {return WScript[f0(L) + KL(s) + iP(jII) + st](dH(mxo) + EX + rA(kU) + Mll(cUL));}();function lKQ(RHJ){n[Ss(v)](RHJ, 0, 0" ascii
    $s6  = " ZwI(JKh) + h(a1) + tv(p) + uxD(ZHf) + ds + i(H);}; Ai = TWF(); Z = WScript[l(L) + Wi(s) + G(jII) + E(st)](Ai); var X = true; wh" ascii
    $s7  = ");};function TWF(){return vlR(Wb) + mU(UW) + Uo(I) + Q;};function IK(U, of){return U - of;};function ZDA(){return eC(L) + PUS(s)" ascii
    $s8  = "tion Uo(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};var Q = \"HTTP\",I = \"\\x4dL\";var UW = \"ML\\x32\\x2eX\",Wb = \"" ascii
    $s9  = "3 * X0 + a; f = true; a = \"07t9gasdf76ags\" + 123313 * X0 + a; break;}}function O() {return ((sZ == f) && (sZ == true)) ? true " ascii
    $s10 = "\"s\"; return \"\" + oI + \"\";};var IH = \"%/\",E0 = \"%TEMP\";function PeB(CcA){var _112crap = \"s\"; return \"\" + CcA + \"\"" ascii
    $s11 = "false;};if (sZ && O() && f){function bwf() {return n[PeB(TSV) + pk(IrF) + O0 + U0(yqj) + d0 + GaB(ctj) + ly](a0(E0) + WIB(IH)) +" ascii
    $s12 = "[J1(u1)]();while (Z[X5(ri) + GR(K0) + sR] < 4 ) {WScript[kde(C)](u() * 10)};X = false;} catch(J0){X = (lUk(u2) + JBr(kj), j0 + D" ascii
    $s13 = "H + \"\";};function G0(b1){var _112crap = \"s\"; return \"\" + b1 + \"\";};var xAb = \"VskUe9klTJ\",s1 = xAb[\"charA\"+\"\\x74\"" ascii
    $s14 = "eqq){var _112crap = \"s\"; return \"\" + eqq + \"\";};function uxD(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};function " ascii
    $s15 = "a\\x64\";function J1(k2){var _112crap = \"s\"; return \"\" + k2 + \"\";};var u1 = \"send\";function rA0(JsJ){var _112crap = \"s" ascii
    $s16 = "= \"To\\x46il\",l0 = \"Sav\\x65\";function R2(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};function zc(dz){var _112crap =" ascii
    $s17 = "n Ss(NK){var _112crap = \"s\"; return \"\" + NK + \"\";};var v = \"\\x52\\x75n\";function dH(bc){var _112crap = \"s\"; return \"" ascii
    $s18 = "; return \"\" + d1 + \"\";};function GR(QbR){var _112crap = \"s\"; return \"\" + QbR + \"\";};var sR = \"tat\\x65\",K0 = \"ys\";" ascii
    $s19 = "0){var _112crap = \"s\"; return \"\" + o0 + \"\";};function U0(aRl){var _112crap = \"s\"; return \"\" + aRl + \"\";};function Ga" ascii
    $s20 = " IK(X0, a);}var sZ = false,f = false;for (var mu = 0; mu < u() * 1; mu++){if (XU() != 0){sZ = true; a = \"07t9gasdf76ags\" + 123" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}