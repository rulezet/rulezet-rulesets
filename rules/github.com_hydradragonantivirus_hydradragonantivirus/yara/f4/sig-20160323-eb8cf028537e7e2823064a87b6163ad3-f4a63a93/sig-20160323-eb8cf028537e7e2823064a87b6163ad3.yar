rule sig_20160323_eb8cf028537e7e2823064a87b6163ad3 {
  meta:
    description = "datamaliciousorder - file 20160323_eb8cf028537e7e2823064a87b6163ad3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfedf1f47185c9dc27c051d9b1f4a452798c2c51aa4c8b9b3b0926f9b6626b54"

  strings:
    $s1  = "function iIg(Fd){var _112crap = \"s\"; return \"\" + Fd + \"\";};function Nh(VJQ){var _112crap = \"s\"; return \"\" + VJQ + \"\"" ascii
    $s2  = "(),IFw = m0[vl + z0(yL) + S + qn(Rx) + ROr(hx) + w(ldF) + Sh(o)]();WScript[QMK + rk(mkU)](eA());var m0 = new this[VCV(kAb) + s](" ascii
    $s3  = "e\",oU = false;var b = function e() {return WScript[Jz(vKe) + qqz(B) + jlg(ixO) + Z(HUo) + Oyz(OHV)](AZe(lfk) + c0(e0) + Cnt + Z" ascii
    $s4  = " m0[ff(vl) + H0(yL) + S + hh(Rx) + XZ(hx) + ldF + OYo(o)]();WScript[BC(QMK) + X0(mkU)](eA());var m0 = new this[MP(kAb) + Fok(s)]" ascii
    $s5  = " = \"is\",Rx = \"l\";var S = \"Mil\",yL = \"UT\\x43\";var vl = \"get\";function a(h1){var _112crap = \"s\"; return \"\" + h1 + " ascii
    $s6  = "nction iG(b0, Bqe){return b0 - Bqe;};function MEY(){return Uk(vKe) + cww(B) + ixO + HUo + OHV;};/*@cc_on  @if (@_win32 || @_win6" ascii
    $s7  = "true)) ? true : false;};if (wZ && T() && T1){function h() {return b[o1(hX) + lAN(TM) + yvq + A1 + p2(CQ) + waG(mO) + TMj(pa) + m" ascii
    $s8  = "gs\" + 123313 * m1 + PY; T1 = true; PY = \"07t9gasdf76ags\" + 123313 * m1 + PY; break;}}function T() {return ((wZ == T1) && (wZ " ascii
    $s9  = "(e3) + zQd(VlA) + fm]();while (F[eq(pDu) + sk(afz)] < 4 ) {WScript[V0(QMK) + Eb(mkU)](eA() * 10)};nT = false;} catch(m2){nT = (q" ascii
    $s10 = ";function s1(d){var _112crap = \"s\"; return \"\" + d + \"\";};function me(mdu){var _112crap = \"s\"; return \"\" + mdu + \"\";}" ascii
    $s11 = "on sc(sq){var _112crap = \"s\"; return \"\" + sq + \"\";};function Oeu(uo){var _112crap = \"s\"; return \"\" + uo + \"\";};funct" ascii
    $s12 = "b) + Iy(JIu) + tl(TlC) + q1(eo) + vc(q0) + a2 + Zk + B2(ffi) + yw(nDd) + gH(dQ) + qY(ix) + s1(I1) + me(r0), false);F[eN(h3) + p3" ascii
    $s13 = "; return \"\" + e1 + \"\";};function OYo(SW){var _112crap = \"s\"; return \"\" + SW + \"\";};function z0(Y){var _112crap = \"s\"" ascii
    $s14 = "0(l){var _112crap = \"s\"; return \"\" + l + \"\";};function Z0(jY){var _112crap = \"s\"; return \"\" + jY + \"\";};var yWj = \"" ascii
    $s15 = "\" + jS + \"\";};function zQd(gJ){var _112crap = \"s\"; return \"\" + gJ + \"\";};var S0 = \"QJDKFe64MGp\",fm = \"d\";var VlA = " ascii
    $s16 = "ar _112crap = \"s\"; return \"\" + K + \"\";};function yh(Xf){var _112crap = \"s\"; return \"\" + Xf + \"\";};var f = \"4JwAP6R" ascii
    $s17 = "turn \"\" + p1 + \"\";};var mkU = \"e\\x65p\",QMK = \"Sl\";function ff(H){var _112crap = \"s\"; return \"\" + H + \"\";};functio" ascii
    $s18 = "\";};function c(pIP){var _112crap = \"s\"; return \"\" + pIP + \"\";};function Zo(N){var _112crap = \"s\"; return \"\" + N + \"" ascii
    $s19 = "function iIg(Fd){var _112crap = \"s\"; return \"\" + Fd + \"\";};function Nh(VJQ){var _112crap = \"s\"; return \"\" + VJQ + \"\"" ascii
    $s20 = "};function waG(ke){var _112crap = \"s\"; return \"\" + ke + \"\";};function TMj(WPs){var _112crap = \"s\"; return \"\" + WPs + " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}