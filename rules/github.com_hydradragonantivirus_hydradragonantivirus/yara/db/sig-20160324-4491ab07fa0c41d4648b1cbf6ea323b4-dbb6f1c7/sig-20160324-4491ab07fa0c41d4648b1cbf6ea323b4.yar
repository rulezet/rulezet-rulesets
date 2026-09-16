rule sig_20160324_4491ab07fa0c41d4648b1cbf6ea323b4 {
  meta:
    description = "datamaliciousorder - file 20160324_4491ab07fa0c41d4648b1cbf6ea323b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f453d58b59b6a6d146a161b548fd60089682cfbfa27559e2445d1d22cb371c9"

  strings:
    $s1  = "var WS = \"\\x63los\\x65\";function YE(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var r0 = \"\\x65\",O0 = \"T\\x6fFil\"" ascii
    $s2  = "() {return JMa[gt + U0 + xk + lDx + X0 + U1](W0 + th) + qUW + biq + qRK + VC + V(O);}; jx = RAr(); cKs = WScript[X](jx); var BJ " ascii
    $s3  = "\",AOA = \"\\x43\\x72e\\x61\";var mxQ = false,X = \"CreateObject\";var JMa = function Etd() {return WScript[X](gE(oc) + i(v) + Q" ascii
    $s4  = "gd = (1, 2, 3, 4, 5, K); return gd;};w = WScript[TTS()](wEB + ju + KU(Yb));jx = w;jx[(lWw)]();jx[z] = Xi(1);jx[sn0(La) + Hy](cKs" ascii
    $s5  = "bg());var Jcy = new this[sn(sa)](),xsl = Jcy[SDD(uwJ) + IK(kC) + zv(J) + N]();WScript[uC](bg());var Jcy = new this[sa](),d = Jcy" ascii
    $s6  = "unction bg(){return 22;};var e = 0,o = 0;function Nm(){var Jcy = new this[sa](),FpJ = Jcy[uwJ + kC + J + q(N)]();WScript[Z(uC)](" ascii
    $s7  = "6ags\" + 123313 * e + o; break;}}function NBF() {return ((wIg == true) && (wIg == P)) ? 1 : p;};if (wIg && NBF() && P){function " ascii
    $s8  = ") + wa + uo] < 4 ) {WScript[s](bg() * 10)};BJ = p;} catch(zoP){BJ = (p3 + f, DgI + U2, ZO + ckn(Qld), 2);};}function Xi(K) {var " ascii
    $s9  = "\"; return \"\" + hrE + \"\";};function SDD(Lwo){var _112crap = \"s\"; return \"\" + Lwo + \"\";};function IK(e0){var _112crap =" ascii
    $s10 = "(var WJi = p; WJi < bg() * 1; WJi++){if (Nm() != p){wIg = true; o = \"07t9gasdf76ags\" + 123313 * e + o; P = true; o = \"07t9gas" ascii
    $s11 = "var WS = \"\\x63los\\x65\";function YE(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var r0 = \"\\x65\",O0 = \"T\\x6fFil\"" ascii
    $s12 = "rap = \"s\"; return \"\" + Qu + \"\";};var Yb = \"\\x65am\",ju = \"B\\x2eStr\";var wEB = \"AD\\x4f\\x44\";function ckn(UhV){var " ascii
    $s13 = "Ne = \"\\x73en\\x64\";function NJy(LL){var _112crap = \"s\"; return \"\" + LL + \"\";};function d0(DyG){var _112crap = \"s\"; re" ascii
    $s14 = "\"\";};function b(r){var _112crap = \"s\"; return \"\" + r + \"\";};var N = \"\\x6e\\x64s\",J = \"isec\\x6f\";var kC = \"CM\\x69" ascii
    $s15 = "[s0(uwJ) + kC + b(J) + N]();var e = \"n\";e = W(xsl, FpJ);var o = \"Q\";o = W(d, xsl);return W(e, o);}var wIg = false,P = false;" ascii
    $s16 = "\";var R = \"D\\x61te\";function Z(D){var _112crap = \"s\"; return \"\" + D + \"\";};var uC = \"Sle\\x65p\";function q(hrE){var " ascii
    $s17 = "n \"\" + e0 + \"\";};function zv(Wr){var _112crap = \"s\"; return \"\" + Wr + \"\";};function s0(Mz){var _112crap = \"s\"; retur" ascii
    $s18 = "(Yr){var _112crap = \"s\"; return \"\" + Yr + \"\";};var O = \"\\x78e\",VC = \"\\x64\\x41.e\";var qRK = \"TX\\x4fa\",biq = \"\\x" ascii
    $s19 = "tion Fil(PZ){var _112crap = \"s\"; return \"\" + PZ + \"\";};var uo = \"\\x65\",wa = \"\\x79st\\x61t\";var t = \"rea\\x64\",di =" ascii
    $s20 = "65tUT\";function sn(p1){var _112crap = \"s\"; return \"\" + p1 + \"\";};var sa = \"D\\x61\\x74e\",NN = \"\\x52un\";var p0 = \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}