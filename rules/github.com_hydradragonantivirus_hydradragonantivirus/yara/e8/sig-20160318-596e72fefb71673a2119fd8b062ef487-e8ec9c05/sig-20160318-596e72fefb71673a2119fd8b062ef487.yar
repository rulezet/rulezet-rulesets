rule sig_20160318_596e72fefb71673a2119fd8b062ef487 {
  meta:
    description = "datamaliciousorder - file 20160318_596e72fefb71673a2119fd8b062ef487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ba7494ce4b18c30ee303c7dd116e3bbf980f6659d92a88fb2d21944b904bd71"

  strings:
    $s1  = "var PNS = \"\\x69n\\x21\";var zrtG = \"g\\x61\";var laDCh = \"try a\";var oM = \", \";var i = \"\\x6c\\x65a\\x73e\";var s2 = \"P" ascii
    $s2  = ";var Rbj = function AwpQ() {return WScript[(function hMBv(){return flPHa;}()) + (V) + (function PPK(){return nPSJ;}()) + (functi" ascii
    $s3  = " hepnL(){return t;}())](OzHNw() * 10)};N = WScript[DtN()]((fTFi) + (function cR(){return uLsqK;}()) + (xfa));N[((function Sd(){r" ascii
    $s4  = " 4 ) {WScript[(function Vd(){return eiSyP;}()) + (function fdMqv(){return bxUcW;}()) + (function vAS(){return e;}()) + (function" ascii
    $s5  = "}()) + (function bVPdB(){return Jd;}()) + (function bzp(){return scmZZ;}())]();WScript[(function k(){return eiSyP;}()) + (functi" ascii
    $s6  = "Script[(function cit(){return eiSyP;}()) + (function zuxqd(){return bxUcW;}()) + (function W(){return e;}()) + (function vwis(){" ascii
    $s7  = "urn QPybN;}()) + (function YJuhf(){return y;}()); CkLJ = WMd(); QuVIG = WScript[(function epvT(){return flPHa;}()) + (function f" ascii
    $s8  = ") + (function Zyo(){return BU;}()) + (IK) + (jB);}else{WScript.Echo((s2) + (function sA(){return i;}()) + (function UHn(){return" ascii
    $s9  = "n XeyXs;}()) + (function bCgPs(){return njPAN;}()) + (function JBJMC(){return XPbl;}());};function M(L, oxh){return L - oxh;};fu" ascii
    $s10 = ") {return xZBLX && aF;};if (zdIzM()){whTj = Rbj[(mTl) + (function ULbK(){return ZjPbY;}()) + (function IZB(){return D;}()) + (dI" ascii
    $s11 = "(){return XNn;}()) + (function lZfIA(){return Tf;}()) + (function WvtmU(){return Jd;}()) + (function Kx(){return scmZZ;}())]();W" ascii
    $s12 = "tV) + (function pp(){return vF;}()) + (function gWXM(){return s1;}()) + (function JwfHJ(){return eLe;}()) + (lZa) + (function ap" ascii
    $s13 = "turn vp;}()) + (function a0(){return kBJu;}()) + (function Wd0(){return qViNJ;}()) + (function xdu(){return zIKBe;}()) + (functi" ascii
    $s14 = "return t;}())](OzHNw());var FnxJU = new this[(Rt) + (function kRtk(){return J;}())]();var C = FnxJU[(function jKB(){return c0;}(" ascii
    $s15 = ")) + (ihqXL) + (function BOF(){return XNn;}()) + (function AaS(){return Tf;}()) + (function Fg(){return Jd;}()) + (function s0()" ascii
    $s16 = ";}()) + (function AXV(){return rt;}()) + (function e0(){return efj;}()) + (function U0(){return wrNEK;}()) + (function TRd(){ret" ascii
    $s17 = " oM;}()) + (laDCh) + (function y0(){return zrtG;}()) + (function eo(){return PNS;}()));}" fullword ascii
    $s18 = "eturn dZrn;}())]();QF(whTj);itI = \"\" + (function SRuFz(){return Tk;}()) + (function cEv(){return iTT;}()) + (function EtsKw(){" ascii
    $s19 = "GTb(){return Pt;}())]((vXOX) + (function X(){return VP;}())) + (vPL) + (function Wd(){return d;}()) + (function gndP(){return W0" ascii
    $s20 = "+ (function UbLEd(){return lxzHO;}()) + xZBLX ? (function gS0(){return aF0;}()) + (cBKKX) + (function p(){return I0;}()) : (cirm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}