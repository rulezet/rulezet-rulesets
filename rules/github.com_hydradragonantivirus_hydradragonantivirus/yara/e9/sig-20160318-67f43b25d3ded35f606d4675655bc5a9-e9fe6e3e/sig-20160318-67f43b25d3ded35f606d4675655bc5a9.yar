rule sig_20160318_67f43b25d3ded35f606d4675655bc5a9 {
  meta:
    description = "datamaliciousorder - file 20160318_67f43b25d3ded35f606d4675655bc5a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "528b14655b717a18dea27243271a634e16ee7778af7fd9ac64c57acc73e49090"

  strings:
    $s1  = "var avICN = \"KNecY!yvURp\"[\"charAt\"](5);var i1 = \"a\\x69n\";var VjFBj = \"r\\x79 ag\";var Qwnvm = \"e, \\x74\";var kb = \"" ascii
    $s2  = "t;}()) + (function c1(){return G;}()) + (function g(){return PlQuH;}()); wHwVq = K(); aZkSv = WScript[(function zoRk(){return Sr" ascii
    $s3  = ") + (FrH) + (function d(){return xGoO;}()) + (function grgbA(){return htacZ;}()) + (function gNU(){return O0;}())]();WScript[(fu" ascii
    $s4  = "(){return Pre;}()) + (function Wc(){return pVBy;}());}else{WScript.Echo((szaDW) + (function pEF(){return kb;}()) + (Qwnvm) + (fu" ascii
    $s5  = " FrH;}()) + (function vOEh(){return xGoO;}()) + (function OhKO(){return htacZ;}()) + (function PUfu(){return O0;}())]();WScript[" ascii
    $s6  = "DV(){return M0;}())] < 4 ) {WScript[(function cF(){return z;}()) + (function Qk(){return lNa;}())](FyuWW() * 10)};gOquL = WScrip" ascii
    $s7  = "d) + (gg) + (RAwYY) + (function ti(){return Mawx;}());};function f(rADn, gPAu){return rADn - gPAu;};function TXEp(){return (func" ascii
    $s8  = "se;for (var JUaH = 0; JUaH < FyuWW() * 1; JUaH++){if (JZAZj() != 0){bl = true;xRB = true;break;}}function MfqOi() {return bl && " ascii
    $s9  = " {return WScript[(SrZ) + (function sVW(){return dpNca;}()) + (function c(){return Z;}()) + (function iCnFz(){return xfCe;}()) + " ascii
    $s10 = "t[TXEp()]((function aRdg(){return PTy;}()) + (function Xaz(){return HcJ;}()) + (function pn(){return fDgS;}()) + (Q) + (function" ascii
    $s11 = "nction f1(){return VjFBj;}()) + (function RBN(){return i1;}()) + (function r0(){return avICN;}()));}" fullword ascii
    $s12 = "on Dfa(){return ndDOV;}()) + (function mz(){return B;}()) + (kV) + (function azLeg(){return qWo;}()) + (function cF0(){return cW" ascii
    $s13 = "+ (function uFD(){return A0;}()) + (function h(){return Jep;}()) + (function x(){return b0;}()) + (function ECqn(){return s;}())" ascii
    $s14 = ")))]();gOquL[(KuZ) + (xLPGV)] = 1;gOquL[(function lIJc(){return Qhqn;}())](aZkSv[(aGL) + (function X0(){return GczS;}()) + (func" ascii
    $s15 = "()) + (function SqIn(){return LoYY;}()) + (function sd(){return qbBCb;}());};function FyuWW(){return 22;};function JZAZj(){var k" ascii
    $s16 = "CIO;}()) + (function Qfguj(){return uEPx;}())] = 0;gOquL[(function QE(){return PdQd;}()) + (function JKcVX(){return ZG;}()) + (f" ascii
    $s17 = "xb;}()) + (function rHe(){return Uwfl;}()) + (dRd) + (rli) + (function r(){return esb;}()) + (function RM(){return dP;}()) + (XW" ascii
    $s18 = "n ajOr(){return SPi;}()));}();function fAeXj(E){R[(hwePM)](E, 0, 0);};function K(){return (function W(){return aKLB;}()) + (SzgX" ascii
    $s19 = "ction Z0(){return zo;}())]();var i = kU[(function eXpuQ(){return O;}()) + (function bZN(){return i0;}()) + (function c0(){return" ascii
    $s20 = "unction RO(){return bwpb;}())](VXhz, 2 );gOquL[(function ht(){return s0;}()) + (function sHV(){return oTnvh;}()) + (function XK(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}