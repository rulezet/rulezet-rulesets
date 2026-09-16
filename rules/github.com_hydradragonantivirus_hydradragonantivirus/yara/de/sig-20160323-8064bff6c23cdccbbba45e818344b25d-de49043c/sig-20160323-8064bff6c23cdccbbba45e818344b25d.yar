rule sig_20160323_8064bff6c23cdccbbba45e818344b25d {
  meta:
    description = "datamaliciousorder - file 20160323_8064bff6c23cdccbbba45e818344b25d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "971a16112eecbd732e1fe7f5feb85fda7051d5cd21593678edd3e0db02f7b9b1"

  strings:
    $s1  = ") + BHy(oxY) + EcS + mzG(Rj)]();WScript[Ha + oCb(hne)](Lo());var L = new this[qH + mQv(K)](),o = L[WPY(m) + AVo(CD) + N0 + W(oxY" ascii
    $s2  = ", 4, 5, D); return mC;};OPU = (vMT) ? 14134 : 414234;PWz = WScript[zM()](f2(qY) + I2(T2) + Q0(VUL) + gsk(cTy));b = PWz;tm = (WUQ" ascii
    $s3  = "(pAN) + S(i) + xBG(CfJ), false);aRP[F0 + hw(loV)]();while (aRP[zKV + EB(hpH) + oE(oj)] < 4 ) {WScript[GvC(Ha) + gPo(hne)](Lo() *" ascii
    $s4  = "n tN() {return WScript[D0(MX) + T(qk) + EW(dgA) + c + JuF(ArZ)](V(Pv) + BQH + hM(r) + NAf(MRH) + N(p) + p0(hhg));}();function U(" ascii
    $s5  = "sdf76ags\" + 123313 * OPU + tm; break;}}function TS() {return ((vMT == WUQ) && (vMT == true)) ? true : false;};if (vMT && TS() &" ascii
    $s6  = ") + F(EcS) + Rj]();WScript[Ha + k(hne)](Lo());var L = new this[owj(qH) + Ai(K)](),vz = L[cAl(m) + WJm(CD) + nPp(N0) + e(oxY) + g" ascii
    $s7  = "function Zf(OAB){var _112crap = \"s\"; return \"\" + OAB + \"\";};function x(cW){var _112crap = \"s\"; return \"\" + cW + \"\";}" ascii
    $s8  = "function Zf(OAB){var _112crap = \"s\"; return \"\" + OAB + \"\";};function x(cW){var _112crap = \"s\"; return \"\" + cW + \"\";}" ascii
    $s9  = "ap = \"s\"; return \"\" + c1 + \"\";};function WPY(vbs){var _112crap = \"s\"; return \"\" + vbs + \"\";};function AVo(sU){var _1" ascii
    $s10 = "Is){var _112crap = \"s\"; return \"\" + bIs + \"\";};function qd(hYQ){var _112crap = \"s\"; return \"\" + hYQ + \"\";};var o1 = " ascii
    $s11 = " \"seco\\x6e\";var oxY = \"i\",N0 = \"C\\x4d\\x69\\x6cl\";var CD = \"tUT\",m = \"ge\";function LxK(zZY){var _112crap = \"s\"; re" ascii
    $s12 = "o\",c3 = bNa[\"\"+\"\\x63\"+\"har\"+\"\\x41\"+\"t\"](5);function H1(sOy){var _112crap = \"s\"; return \"\" + sOy + \"\";};functi" ascii
    $s13 = "ion QVv(PP){var _112crap = \"s\"; return \"\" + PP + \"\";};function DTN(q2){var _112crap = \"s\"; return \"\" + q2 + \"\";};fun" ascii
    $s14 = " = \"e\";var MOY = \"g\",Wnt = \"\\x44a\\x74e\";function oCb(Ci){var _112crap = \"s\"; return \"\" + Ci + \"\";};function k(W0){" ascii
    $s15 = "x63\\x72i\";var BQH = \"S\",Pv = \"W\";function D0(L1){var _112crap = \"s\"; return \"\" + L1 + \"\";};function T(WbE){var _112c" ascii
    $s16 = " c0 + \"\";};function p0(lP){var _112crap = \"s\"; return \"\" + lP + \"\";};var hhg = \"\\x6cl\",p = \"\\x53he\";var MRH = \"p" ascii
    $s17 = "tion oE(b3){var _112crap = \"s\"; return \"\" + b3 + \"\";};var oj = \"ate\",hpH = \"dyst\";var zKV = \"\\x72ea\";function hw(b2" ascii
    $s18 = "){var _112crap = \"s\"; return \"\" + rjd + \"\";};var Mm = \"jGPwnfbnmJ\",cw = \"Bod\\x79\";var bh0 = \"\\x73e\",eq = Mm[\"\"+" ascii
    $s19 = "turn \"\" + y1 + \"\";};var hne = \"\\x65e\\x70\",Ha = \"Sl\";function sUx(Rn){var _112crap = \"s\"; return \"\" + Rn + \"\";};f" ascii
    $s20 = "1(CT){var _112crap = \"s\"; return \"\" + CT + \"\";};function H0(cQ){var _112crap = \"s\"; return \"\" + cQ + \"\";};var ab = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}