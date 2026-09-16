rule sig_20160324_a58c442dc78494f652020f4d32285d0b {
  meta:
    description = "datamaliciousorder - file 20160324_a58c442dc78494f652020f4d32285d0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c0c66d2d6e1bb502b4dae4101eaa38e8c6a466c76d7e7cb1b2a1d228a502ed"

  strings:
    $s1  = "\"CreateObject\";var J0 = function bM() {return WScript[l](oz + V + jz + h);}();var s = 123213,upY = \"MSXML2.XMLHTTP\";var Wj =" ascii
    $s2  = "var CiB = \"clo\\x73e\";function B1(nNw){var _112crap = \"s\"; return \"\" + nNw + \"\";};var sM = \"\\x6fFil\\x65\",M0 = \"Sav" ascii
    $s3  = "Q0 + kE + oQV]();WScript[fsj](cE());var z = new this[vCw](),nD = z[Z + WE(DTe) + Q0 + Z0(kE) + oQV]();var Td = \"M\";Td = xwg(E," ascii
    $s4  = " jgx(th)) + Mm + Opl + U0(YEQ) + gWC;}; S = q(); YZ = WScript[l](S); var J = 1; while (J){try {YZ[glF(B)](IeO, ny(yeN) + d + d0(" ascii
    $s5  = "zm){J = (AXR + pUI(U1), t + CX(xVO), uGn + De, 2);};}function MXS(vrh) {var Y = (1, 2, 3, 4, 5, vrh); return Y;};e = WScript[uE(" ascii
    $s6  = "n VQj(){var z = new this[vCw](),r = z[Z + l0(DTe) + Q0 + kE + oQV]();WScript[fsj](cE());var z = new this[vCw](),E = z[Z + DTe + " ascii
    $s7  = "r _112crap = \"s\"; return \"\" + GbJ + \"\";};var oQV = \"d\\x73\",kE = \"ec\\x6fn\";var Q0 = \"ll\\x69s\",DTe = \"TCM\\x69\";v" ascii
    $s8  = "3213,I = 0;function MX(uei){J0[pZC](uei, I, I);};function q(){return upY;};function xwg(Lqf, At){return Lqf - At;};function uE()" ascii
    $s9  = "eturn ((D == true) && (D == U)) ? 1 : I;};if (D && wJe() && U){function iv() {return J0[DSL(RZ) + I0 + Aal + q0(W) + i + w](V1 +" ascii
    $s10 = "Viy) + OmL + kO + N + o(ou) + T, false);YZ[N0]();rV = \"Sleep\";while (YZ[wq + DVJ] < 4 ) {WScript[rV](cE() * 10)};J = I;} catch" ascii
    $s11 = "fa\\x64f\\x61\";function pUI(laa){var _112crap = \"s\"; return \"\" + laa + \"\";};var U1 = \"\\x61\",AXR = \"\\x61sdf\";var DVJ" ascii
    $s12 = "\"AD\\x4fD\",De = \"\\x61\";var uGn = \"\\x61fda\\x66\";function CX(I1){var _112crap = \"s\"; return \"\" + I1 + \"\";};var xVO " ascii
    $s13 = "q = \"rea\\x64y\";var F = \"S\\x6c\\x65e\\x70\",N0 = \"sen\\x64\";function ny(RZ0){var _112crap = \"s\"; return \"\" + RZ0 + \"" ascii
    $s14 = "turn \"\" + U2 + \"\";};var QZ = \"o\\x64\\x79\",mw = \"\\x6es\\x65\\x42\";var y = \"\\x52e\\x73p\\x6f\",k = \"\\x77\\x72ite\";f" ascii
    $s15 = ");var Hs = \"JP\";Hs = xwg(nD, E);return xwg(Td, Hs);}var D = false,U = false;for (var K = I; K < cE() * 1; K++){if (VQj() != I)" ascii
    $s16 = "8\";var Opl = \"s\\x31HzL\",Mm = \"N\\x30Wn\\x69\";function jgx(lp){var _112crap = \"s\"; return \"\" + lp + \"\";};var th = \"" ascii
    $s17 = "var CiB = \"clo\\x73e\";function B1(nNw){var _112crap = \"s\"; return \"\" + nNw + \"\";};var sM = \"\\x6fFil\\x65\",M0 = \"Sav" ascii
    $s18 = " V2(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";};var KJ = \"t\\x69o\\x6e\",U3 = \"\\x70os\\x69\";function lN(U2){var _112" ascii
    $s19 = "x70:\";var IeO = \"GE\\x54\";function glF(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};function pw(zpE){var _112crap = \"" ascii
    $s20 = "){var _112crap = \"s\"; return \"\" + O + \"\";};function o(erG){var _112crap = \"s\"; return \"\" + erG + \"\";};var T = \"oa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}