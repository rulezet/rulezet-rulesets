rule sig_20160318_338f98a94b0e0a09d879ea62fc452420 {
  meta:
    description = "datamaliciousorder - file 20160318_338f98a94b0e0a09d879ea62fc452420.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c650a9675973b88ff5cc5a34ec66bce09a231ec0f6da0f83146b6956b5a36357"

  strings:
    $x1  = "var iaE = \"HFQk!ZGVbY\"[\"charAt\"](4);var HgzMJ = \"gain\";var clb = \"ry \\x61\";var D1 = \"\\x20t\";var fCGU = \",\";var ef " ascii
    $s2  = "\\x65c\";var EZ = \"teObj\";var MsS = \"Cr\\x65\\x61\";var XQ = function L() {return WScript[(MsS) + (function WpG(){return EZ;}" ascii
    $s3  = "(SDpuc() * 10)};XoTaC = WScript[D()]((HDIh) + (function ZJAb(){return k;}()) + (LGU) + (function tGxZ(){return i0;}()));XoTaC[((" ascii
    $s4  = "= ThWZ(); WEUPE = WScript[(function meBq(){return MsS;}()) + (function DTn(){return EZ;}()) + (nTxz) + (function bNPZn(){return " ascii
    $s5  = "se{WScript.Echo((function FF(){return hhoY;}()) + (function IPI(){return ef;}()) + (function h0(){return fCGU;}()) + (function P" ascii
    $s6  = "return iPD;}()) + (bqO) + (function hjs(){return LJwK;}()) + (Phw)]();WScript[(function eqSTW(){return UVm;}())](SDpuc());var aX" ascii
    $s7  = "rn bqO;}()) + (function HyD(){return LJwK;}()) + (Phw)]();WScript[(function LIz(){return UVm;}())](SDpuc());var aX = new this[(f" ascii
    $s8  = "fJYf;}()) + (function SJF(){return vGWR;}()) + (function L1(){return toyI;}())] < 4 ) {WScript[(function LvOq(){return UVm;}())]" ascii
    $s9  = "n BR(){return Tol;}());};function FsJA(GFpFb, Uxn){return GFpFb - Uxn;};function D(){return (MsS) + (EZ) + (function WHk(){retur" ascii
    $s10 = "y = 0; Kyuy < SDpuc() * 1; Kyuy++){if (K() != 0){c = true;vL = true;break;}}function M() {return c && vL;};if (M()){rxf = XQ[(j)" ascii
    $s11 = ")) + (function fhod(){return xRAg;}()) + (function rb(){return mUL;}()) + (function Z(){return iPD;}()) + (function yEUrv(){retu" ascii
    $s12 = "unction tIQpH(){return mN;}()) + (function wRuy(){return Gri;}())]();var LtK = aX[(function whW(){return YOgHn;}()) + (xRAg) + (" ascii
    $s13 = ")) + (GMTA) + (function Ohw(){return vgFMN;}()) + (function wo(){return zRb;}())) + (function v0(){return Wa;}()) + (function DO" ascii
    $s14 = "(){return gAab;}()) + (function bOH(){return E;}()) + (function EQJud(){return tLI;}()) + (function d(){return dhVa;}()); Brlqh " ascii
    $s15 = "urn neXDX;}()) + (rtC)] = 0;XoTaC[(function GyL(){return v1;}()) + (function EvJpw(){return Qm;}()) + (Z0)](rxf, 2 );XoTaC[(FSTw" ascii
    $s16 = "Txz) + (function ppB(){return VY;}())]((CIewN) + (function bF(){return dVTr;}()) + (function LggnQ(){return l;}()) + (function I" ascii
    $s17 = "function lBpLN(){return ODD;}()) + (function gh(){return t0;}()))]();XoTaC[(function osPsu(){return bE;}()) + (function ALH(){re" ascii
    $s18 = "return tojYe;}()) + (i1) + (function dG(){return ZZajj;}())]);XoTaC[(function oVNY(){return PS;}()) + (cx) + (function nh0(){ret" ascii
    $s19 = "n mN;}()) + (function yyk(){return Gri;}())]();var u = aX[(YOgHn) + (xRAg) + (function iCcCK(){return mUL;}()) + (function ya(){" ascii
    $s20 = "}())](WEUPE[(function ka(){return hQLe;}()) + (function n(){return SOw;}()) + (function nh(){return FYrEM;}()) + (function M0(){" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}