rule sig_20160324_90c8dd0f716cf66becff26952265a1ce {
  meta:
    description = "datamaliciousorder - file 20160324_90c8dd0f716cf66becff26952265a1ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b78e77723ed4a3c4d128f98b6672c496105a374840da31106821a6e55b11327"

  strings:
    $s1  = "function jzb(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};var K0 = \"\\x65\",agj = \"cl\\x6fs\";function a1(v2){var _112c" ascii
    $s2  = "fG = \"CreateObject\";var kdn = function BtM() {return WScript[OfG](Rme + GZ(z) + IrO);}();var Rzg = 123213,Yfc = \"MSXML2.XMLHT" ascii
    $s3  = "0(WTU)](nEV + f) + dqL(zLs) + amw(HG) + v1;}; Y = w(); ILX = WScript[OfG](Y); var c = 1; while (c){try {ILX[x](MU, K + Y1(Q) + N" ascii
    $s4  = "0;function MxW(){var p = new this[Uq(zSY)](),fE = p[rsb + y + BsJ + Ws]();WScript[Yj](Z());var p = new this[zSY](),Op = p[kk(rsb" ascii
    $s5  = ") + y + BsJ + UY(Ws)]();WScript[Yj](Z());var p = new this[zSY](),TPZ = p[Fip(rsb) + y + yG(BsJ) + Ws]();var xq = \"a\";xq = Ed(O" ascii
    $s6  = "P){c = (gy, L + uen, xzQ + CcY, 2);};}function lC(sL) {var CJz = (1, 2, 3, 4, 5, sL); return CJz;};a0 = WScript[hUc()](z0(fk) + " ascii
    $s7  = ";var C = 2123213,o = 0;function R(yP){kdn[sTh](yP, o, o);};function w(){return Yfc;};function Ed(dQh, D){return dQh - D;};functi" ascii
    $s8  = "b() {return ((bD == true) && (bD == I)) ? 1 : o;};if (bD && Aob() && I){function nx() {return kdn[nnj + Y0 + y1 + CG + v0(g) + D" ascii
    $s9  = " + JLw(BdO) + kb + xbx, false);ILX[wp(P2)]();wL = \"Sleep\";while (ILX[SU + vj + HVe] < 4 ) {WScript[wL](Z() * 10)};c = o;} catc" ascii
    $s10 = "H + \"\";};var j = \"\\x74ion\",gd = \"\\x70osi\";function l(Qm){var _112crap = \"s\"; return \"\" + Qm + \"\";};var Tj = \"\\x6" ascii
    $s11 = "k + \"\";};var IrO = \"hel\\x6c\",z = \"ipt\\x2eS\";var Rme = \"\\x57Scr\",v = \"jec\\x74\";var OOD = \"teO\\x62\",d = \"C\\x72e" ascii
    $s12 = " o){bD = true; w0 = \"07t9gasdf76ags\" + 123313 * xq + w0; I = true; w0 = \"07t9gasdf76ags\" + 123313 * xq + w0; break;}}functio" ascii
    $s13 = "function jzb(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};var K0 = \"\\x65\",agj = \"cl\\x6fs\";function a1(v2){var _112c" ascii
    $s14 = "vj = \"\\x79stat\";var SU = \"re\\x61d\",p0 = \"\\x70\";var fz = \"S\\x6cee\";function wp(g0){var _112crap = \"s\"; return \"\" " ascii
    $s15 = "12crap = \"s\"; return \"\" + Fiw + \"\";};function D0(h){var _112crap = \"s\"; return \"\" + h + \"\";};var WTU = \"\\x73\",g =" ascii
    $s16 = "s\"; return \"\" + Esy + \"\";};function yG(Z0){var _112crap = \"s\"; return \"\" + Z0 + \"\";};var Ws = \"co\\x6eds\",BsJ = \"" ascii
    $s17 = "eturn \"\" + v2 + \"\";};var U1 = \"l\\x65\",INT = \"\\x54oFi\";var Tuo = \"S\\x61v\\x65\";function mA(UvH){var _112crap = \"s\"" ascii
    $s18 = "Ru\\x6e\";var A = \"\\x50\",r = \"L\\x48TT\";var LXT = \"2\\x2e\\x58\\x4d\",S = \"M\\x53X\\x4dL\";function GZ(k){var _112crap = " ascii
    $s19 = "2crap = \"s\"; return \"\" + Wln + \"\";};function UY(Em){var _112crap = \"s\"; return \"\" + Em + \"\";};function Fip(Esy){var " ascii
    $s20 = "y = \"TCM\\x69\\x6c\",rsb = \"ge\\x74\\x55\";function Uq(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};var zSY = \"\\x44a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}