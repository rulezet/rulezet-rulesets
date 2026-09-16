rule sig_20160324_3ae23f11b9dc65d76d95fb37d2285933 {
  meta:
    description = "datamaliciousorder - file 20160324_3ae23f11b9dc65d76d95fb37d2285933.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "259c265e2f45ce24501895b132117a37ba1c6db5730cb82bb14ae6359900f907"

  strings:
    $s1  = "\"\\x43re\\x61\\x74\";var aJ = false,RGE = \"CreateObject\";var xc = function yvF() {return WScript[RGE](gV + yTC(etL) + uw);}()" ascii
    $s2  = ");WScript[E](ds());var e = new this[YVn](),ggh = e[fkN(W) + UB + mw(r) + Sxd + EO]();WScript[E](ds());var e = new this[YVn](),n " ascii
    $s3  = "bIr = c(); ONU = WScript[RGE](bIr); var X = 1; while (X){try {ONU[O0](gcN, Z + g(a0) + jB(pK) + S(QJ) + B + aI(Jp) + YdH, false)" ascii
    $s4  = ", b(oII) + SEe, 2);};}function eh(iIR) {var p = (1, 2, 3, 4, 5, iIR); return p;};tA = WScript[Yt()](B0 + sI + TI);bIr = tA;bIr[(" ascii
    $s5  = "function uX(D0){var _112crap = \"s\"; return \"\" + D0 + \"\";};var I1 = \"\\x65\",RYW = \"\\x63\\x6c\\x6fs\";function Qo(gi){va" ascii
    $s6  = " iDS + Sch; dM = true; Sch = \"07t9gasdf76ags\" + 123313 * iDS + Sch; break;}}function i() {return ((e0 == true) && (e0 == dM)) " ascii
    $s7  = "1 : GIt;};if (e0 && i() && dM){function dxl() {return xc[TXK + VM(Fx) + I + t + Q + KZd](AxW + Lvw(BIP)) + zF(bR) + xtm + oh;}; " ascii
    $s8  = ";ONU[pV]();w = \"Sleep\";while (ONU[Ni + Xk + jp(Ya)] < 4 ) {WScript[w](ds() * 10)};X = GIt;} catch(bz){X = (g0(Qkj), I0(VYb) + " ascii
    $s9  = "\\x64\";var r = \"l\\x69se\",UB = \"C\\x4dil\";var W = \"\\x67\\x65\\x74UT\",YVn = \"\\x44ate\";function pi(BF){var _112crap = " ascii
    $s10 = "\\x65x\\x65\",xtm = \"\\x77\\x4c3g\";var bR = \"\\x4b\\x42C8\";function Lvw(cpJ){var _112crap = \"s\"; return \"\" + cpJ + \"\";" ascii
    $s11 = "5/\",AxW = \"%\\x54EM\";function VM(isB){var _112crap = \"s\"; return \"\" + isB + \"\";};var KZd = \"\\x73\",Q = \"rin\\x67\";v" ascii
    $s12 = "on mw(H){var _112crap = \"s\"; return \"\" + H + \"\";};function J(P){var _112crap = \"s\"; return \"\" + P + \"\";};function dy" ascii
    $s13 = "112crap = \"s\"; return \"\" + eED + \"\";};function WZ(qn){var _112crap = \"s\"; return \"\" + qn + \"\";};var EO = \"\\x73\",S" ascii
    $s14 = "= \"fadf\\x61\";function g0(dUq){var _112crap = \"s\"; return \"\" + dUq + \"\";};var Qkj = \"a\\x73dfa\";function jp(JsQ){var _" ascii
    $s15 = "W = \"\\x43Mil\";var K = \"\\x67\\x65t\\x55\\x54\",l = \"\\x44ate\";var E = \"Sl\\x65ep\";function v(hZk){var _112crap = \"s\"; " ascii
    $s16 = "= e[W + J(UB) + dyd(r) + WZ(Sxd) + EO]();var iDS = \"DEV\";iDS = ep(ggh, h);var Sch = \"LpH\";Sch = ep(n, ggh);return ep(iDS, Sc" ascii
    $s17 = "\"; return \"\" + gq + \"\";};function S(U){var _112crap = \"s\"; return \"\" + U + \"\";};function aI(ilV){var _112crap = \"s\"" ascii
    $s18 = " (aJ){function ds(){return 22;};var iDS = 0,Sch = 0;function DRJ(){var e = new this[YVn](),h = e[v(W) + UB + iPC(r) + Sxd + EO](" ascii
    $s19 = "s\"; return \"\" + gi + \"\";};var m = \"\\x6ce\",yi = \"T\\x6fFi\";var C0 = \"S\\x61ve\",d0 = \"t\\x69\\x6fn\";var t0 = \"pos" ascii
    $s20 = " = \"s\"; return \"\" + R + \"\";};var uw = \"h\\x65ll\",etL = \"\\x69\\x70t.\\x53\";var gV = \"\\x57Scr\",LTb = \"\\x63t\";var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}