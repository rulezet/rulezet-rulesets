rule sig_20160323_bf72b099f56490cc1a91a345b26d070c {
  meta:
    description = "datamaliciousorder - file 20160323_bf72b099f56490cc1a91a345b26d070c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6872cbd89b573e9627329c767fd6caf6492218b6713ed7648de6adff4863d362"

  strings:
    $s1  = "function w3(It){var _112crap = \"s\"; return \"\" + It + \"\";};function s2(cy){var _112crap = \"s\"; return \"\" + cy + \"\";};" ascii
    $s2  = "U(B){var _112crap = \"s\"; return \"\" + B + \"\";};var UEA = \"%/\",m3 = \"\\x25TEMP\";function n(qAB){var _112crap = \"s\"; re" ascii
    $s3  = "]();WScript[hc(Srj) + eEF(aJ)](BC());var pGP = new this[U(j) + PF](),t = pGP[d0(KA) + k0(S) + AZ(x0) + qM(zBy) + pd(b0) + K1(qwv" ascii
    $s4  = ") + sGN(h1) + P(dPe)]();WScript[t2(Srj) + UCC(aJ)](BC());var pGP = new this[Qyy(j) + MR(PF)](),K0 = pGP[out(KA) + FJl(S) + DXZ(x" ascii
    $s5  = "H = M[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](0),gN = \"ate\\x4fb\";var y = \"C\\x72e\",BsH = false;var pO = function TKv() {ret" ascii
    $s6  = "mq) + W0 + qFo(jP) + O0;}; Bh = Rrx(); gmx = WScript[y + gN + H + qe + eFk](Bh); var UqH = true; while (UqH){try {gmx[T0(T) + Jj" ascii
    $s7  = "c\\x69\",OXy = \"\\x54\\x43Mil\";var K2 = \"getU\",Dw = \"te\";var Ir = \"Da\";function hc(W){var _112crap = \"s\"; return \"\" " ascii
    $s8  = "n Rrx(){return AY + vCH(k) + d(bSq) + dqx;};function qa(t1, Go){return t1 - Go;};function nHz(){return GD(y) + HJS(gN) + h0(H) +" ascii
    $s9  = "; r = \"07t9gasdf76ags\" + 123313 * Q + r; break;}}function K() {return ((rl == jsx) && (rl == true)) ? true : false;};if (rl &&" ascii
    $s10 = "() && jsx){function D() {return pO[n(Z0) + rqD(Pc) + l0(nJS) + Kh(q1) + fp + H2(m2) + xd(Ffi)](m3 + eyU(UEA)) + jFd + I0 + vjD(m" ascii
    $s11 = "gmx[QTy(d1) + D0 + FN(Hop)] < 4 ) {WScript[Rk(Srj) + suA(aJ)](BC() * 10)};UqH = false;} catch(hg){UqH = (w1 + u2(ytY), Ucd(JDi) " ascii
    $s12 = "65\",Bs = \"\\x63l\\x6f\\x73\";function s0(g){var _112crap = \"s\"; return \"\" + g + \"\";};function ZKz(uOC){var _112crap = \"" ascii
    $s13 = "0) + zBy + b0 + qhM(qwv) + e(h1) + FS(dPe)]();var Q = \"c\";Q = qa(t, ADb);var r = \"Cf\";r = qa(K0, t);return qa(Q, r);}var rl " ascii
    $s14 = "d(YB){var _112crap = \"s\"; return \"\" + YB + \"\";};function NO(WZe){var _112crap = \"s\"; return \"\" + WZe + \"\";};function" ascii
    $s15 = "eturn \"\" + iwF + \"\";};function ZAl(i){var _112crap = \"s\"; return \"\" + i + \"\";};function KC(Wx){var _112crap = \"s\"; r" ascii
    $s16 = "rap = \"s\"; return \"\" + Vv + \"\";};function u(yB){var _112crap = \"s\"; return \"\" + yB + \"\";};function YE(iwF){var _112c" ascii
    $s17 = " \"\";};function GD(Hhl){var _112crap = \"s\"; return \"\" + Hhl + \"\";};function HJS(H0){var _112crap = \"s\"; return \"\" + H" ascii
    $s18 = " = \"\\x52es\";function t4(yl){var _112crap = \"s\"; return \"\" + yl + \"\";};function I1(kH){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "){var _112crap = \"s\"; return \"\" + aD + \"\";};var M = \"j\",HOJ = \"qitB\";var eFk = HOJ[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A" ascii
    $s20 = "ction h0(H1){var _112crap = \"s\"; return \"\" + H1 + \"\";};function fi(yW){var _112crap = \"s\"; return \"\" + yW + \"\";};fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}