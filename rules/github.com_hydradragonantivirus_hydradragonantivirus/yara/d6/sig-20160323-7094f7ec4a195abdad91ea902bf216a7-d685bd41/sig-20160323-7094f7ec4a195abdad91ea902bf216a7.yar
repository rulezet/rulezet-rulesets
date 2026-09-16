rule sig_20160323_7094f7ec4a195abdad91ea902bf216a7 {
  meta:
    description = "datamaliciousorder - file 20160323_7094f7ec4a195abdad91ea902bf216a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db44312481ee6956e109eb2921b0dcec0cc05b1a8703e7ea7cfda96d5df5117"

  strings:
    $s1  = "function bk(Qqg){var _112crap = \"s\"; return \"\" + Qqg + \"\";};var an = \"cl\\x6fse\";function f0(ntB){var _112crap = \"s\"; " ascii
    $s2  = " = \"%TEMP\";function UOJ(v2){var _112crap = \"s\"; return \"\" + v2 + \"\";};function V0(Y0){var _112crap = \"s\"; return \"\" " ascii
    $s3  = "t\"](3),lL = \"re\";var krF = \"C\",DCu = false;var Nl = function zp() {return WScript[I(krF) + SR(lL) + Sbv(Hu) + rKG + Tp(y) +" ascii
    $s4  = ");}; G = sm(); IT = WScript[krF + M(lL) + Km(Hu) + si(rKG) + zk(y) + rx(yd) + Bu](G); var s = true; while (s){try {IT[AK(w) + QM" ascii
    $s5  = "rn t0(C) + x1 + k0(Dp) + JSN(nR);};function Ey(uNv, m){return uNv - m;};function wzJ(){return Hm(krF) + vqE(lL) + vy(Hu) + rKG +" ascii
    $s6  = "hile (IT[k1(F) + xw + TtI(Lr)] < 4 ) {WScript[d + PY(rns) + Xm(KiN)](n() * 10)};s = false;} catch(v0){s = (ZC(uwz) + jLQ(h), Ft0" ascii
    $s7  = "= \"s\"; return \"\" + hWL + \"\";};function zy(MMt){var _112crap = \"s\"; return \"\" + MMt + \"\";};function en(c0){var _112cr" ascii
    $s8  = " = \"pe\\x6e\",g2 = r0[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](1);function w1(X0){var _112crap = \"s\"; return \"" ascii
    $s9  = "\"s\"; return \"\" + c + \"\";};function Rt(nY){var _112crap = \"s\"; return \"\" + nY + \"\";};function bJ(B0){var _112crap = " ascii
    $s10 = "n\",dAR = \"Ru\";function BW(S){var _112crap = \"s\"; return \"\" + S + \"\";};function YJ(x0){var _112crap = \"s\"; return \"\"" ascii
    $s11 = "var d = \"S\";function Xd(qDn){var _112crap = \"s\"; return \"\" + qDn + \"\";};function li(qcP){var _112crap = \"s\"; return \"" ascii
    $s12 = "on N1(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};var QH = \"\\x69on\",WT = \"posi\\x74\";function JQ(Qwf){var _112crap " ascii
    $s13 = "pt[d + ne(rns) + KiN](n());var v = new this[kcE + Xh(Rn) + LI](),upu = v[Y(ZPS) + Rt(PQ) + bJ(yeJ) + V(A) + g(nO)]();var x = \"e" ascii
    $s14 = "v(R){var _112crap = \"s\"; return \"\" + R + \"\";};function rt(yN){var _112crap = \"s\"; return \"\" + yN + \"\";};function ul(" ascii
    $s15 = "2crap = \"s\"; return \"\" + ICG + \"\";};var muR = \"cguqtZbd\",rfP = \"ream\";var qK = muR[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"\"" ascii
    $s16 = "r _112crap = \"s\"; return \"\" + dg + \"\";};function Tp(EHn){var _112crap = \"s\"; return \"\" + EHn + \"\";};function xHj(Sy)" ascii
    $s17 = "urn \"\" + ckt + \"\";};function vqE(qXk){var _112crap = \"s\"; return \"\" + qXk + \"\";};function vy(jq){var _112crap = \"s\";" ascii
    $s18 = "\"\\x42.S\";var s4 = \"OD\",A0 = \"AD\";function YIt(o1){var _112crap = \"s\"; return \"\" + o1 + \"\";};var iEE = \"\\x66\\x61" ascii
    $s19 = "turn \"\" + c0 + \"\";};var r = \"\\x65\\x6e\",w = \"\\x6fp\";var S4 = \"C1TW\",KtH = \"fP0jrI\";var Dhx = \"t\",m1 = \"c\";var " ascii
    $s20 = "tion JSN(uMp){var _112crap = \"s\"; return \"\" + uMp + \"\";};var nR = \"TT\\x50\",Dp = \"X\\x4d\\x4cH\";var x1 = \"\\x4d\\x4c2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}