rule sig_20160321_5641cfc006327d77b2b26e6cb7be8a74 {
  meta:
    description = "datamaliciousorder - file 20160321_5641cfc006327d77b2b26e6cb7be8a74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bf4121de00989e548f570a27328d7de7b61b211d970dd7d2f76087f9c252764"

  strings:
    $s1  = "var ZN = \"\\x32\";var iB = \"6816\";var pN = \"\\x32\\x3183\";function m0(xr){return xr;};var XhBVW = \"\\x73\\x64f\";var eMI =" ascii
    $s2  = "= vPU[\"charAt\"](1);var iLJNB = \"r\\x65a\";var KuVcM = zbXB[\"charAt\"](4);var LhSki = function oXuoK() {return WScript[WC(KuV" ascii
    $s3  = "gOX;}())) + uLrf(HWKpf) + yD + mFoJB(ih) + tqMXi(ELMXV) + TRY(ngL); xktX = KL(); tDW = WScript[KuVcM + (function WIB(){return iL" ascii
    $s4  = "}bQ = WScript[a()]((function oe(){return habwM;}()) + (function Uv(){return npx;}()) + jeekL(yS) + (function SM(){return dZV;}()" ascii
    $s5  = "DQ(p)]();WScript[YhpC + (function F0(){return gY;}()) + aABLn + (function yIPAS(){return P;}()) + (function LQYZ(){return EFcSW;" ascii
    $s6  = "n XPc(){return p;}())]();WScript[K(YhpC) + D0(gY) + (function bnYc(){return aABLn;}()) + NvYd(P) + rqude(EFcSW)](BX());var O = n" ascii
    $s7  = " false);tDW[(function ih0(){return eB;}()) + N(EMg)]();while (tDW[(function ox(){return HjaC;}()) + k + Rl] < 4 ) {WScript[jX(Yh" ascii
    $s8  = " \".XML\";var q = \"\\x53\\x58\\x4d\\x4c2\";var Xf = \"\\x4d\";function Z0(dp){return dp;};var NfW = \"7LnBnzFd\";var th = NfW[" ascii
    $s9  = "dbm;}()) + viCks(JrPWX) + (function zJePs(){return vXh;}());};function hHwto(vXUbf, l){return vXUbf - l;};function a(){return (f" ascii
    $s10 = "}function ARGjK() {return iccu && eDW;};if (ARGjK()){EU = LhSki[QgHD(Pd) + Uj(hN) + ttpW(Sw) + (function TJ(){return qliG;}()) +" ascii
    $s11 = "IzA;};function glF(q1){return q1;};var Rp = \"LSp\";var wRn = \"XhgpsH\";var EFcSW = wRn[\"charAt\"](3);var P = \"e\";var aABLn " ascii
    $s12 = "n Gmg(GBnC){return GBnC;};function G0(Gl){return Gl;};var p0 = \"LreYOt\";var O1 = \"Zh\";var qFNg = \"gdas\\x63\";var VJ = O1[" ascii
    $s13 = "n USM(OAtBg){return OAtBg;};var JWG = \"8Y4nKBA\";var OlhE = JWG[\"charAt\"](3);var yuCJm = \"i\\x6f\";var CBq = \"p\\x6f\\x73it" ascii
    $s14 = "r gY = \"\\x6c\";var YhpC = Rp[\"charAt\"](1);function DUY(fJ){return fJ;};function ARJ(q0){return q0;};function RzDQ(zHKhp){ret" ascii
    $s15 = ";var GVR = G[\"charAt\"](5);function f(yO){return yO;};function viCks(KU){return KU;};var vXh = \"T\\x54P\";var JrPWX = \"H\";va" ascii
    $s16 = ";var u = \"wr\\x69te\";function t0(Y0){return Y0;};var w = \"t\";var wWzc = \"yp\\x65\";var dFQMa = w[\"charAt\"](0);var zzCW = " ascii
    $s17 = "i(OBz){return OBz;};var oAPl = \"CSEKQBf\";var uFgOX = \"\\x4d\\x50%/\";var J = oAPl[\"charAt\"](2);var x = \"\\x25\\x54\";funct" ascii
    $s18 = ";var ngL = \".\\x65x\\x65\";var ELMXV = \"4\\x49Nl\";var ih = DEoq[\"charAt\"](1);var yD = \"\\x51bR\\x30e\";var HWKpf = \"fyp5" ascii
    $s19 = "\"damen\";var a1 = p0[\"charAt\"](2);var hX = \"r\\x72\";var EOH = \"//a\";var pn = \"htt\\x70:\";var hd = \"G\\x45T\";function " ascii
    $s20 = " p = \"\\x73\";var WkOzZ = \"cond\";var F = \"i\\x73\\x65\";var npB = \"il\\x6c\";var KM = \"getM\";function qRLni(U0){return U0" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}