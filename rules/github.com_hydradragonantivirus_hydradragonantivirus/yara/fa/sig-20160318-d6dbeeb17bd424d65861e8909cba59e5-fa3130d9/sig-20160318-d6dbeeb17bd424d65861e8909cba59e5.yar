rule sig_20160318_d6dbeeb17bd424d65861e8909cba59e5 {
  meta:
    description = "datamaliciousorder - file 20160318_d6dbeeb17bd424d65861e8909cba59e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c563f3f4de0c860e87d2ce40ce7fa336088d1e8e9f7d1570098ab55d22f6d151"

  strings:
    $x1  = "var qJw = \"lPMZU!Kwpjk\"[\"charAt\"](5);var vhYF = \"ga\\x69n\";var wYCMF = \"y a\";var QWngP = \"tr\";var rKK = \"\\x2c \";var" ascii
    $s2  = ";}()); DYfmN = uPF(); FcuJ = WScript[(function gOb(){return zNvj;}()) + (myH) + (AHP) + (h)](DYfmN);FcuJ[(pT) + (function BO(){r" ascii
    $s3  = "tion AT(){return m;}()) + (HUjSv)](glx() * 10)};dnf = WScript[XjrYT()]((L) + (function ycIR(){return Tq;}()) + (function OC(){re" ascii
    $s4  = "(GAu) + (function lSxZT(){return WESYV;}()) + (e0) + (function y(){return b;}())]();WScript[(function d(){return yoR;}()) + (fun" ascii
    $s5  = "(function jZCoW(){return Bh;}()) + (function BtPU(){return Z;}()) + (function U(){return DNJt;}())] < 4 ) {WScript[(yoR) + (func" ascii
    $s6  = "){return GAu;}()) + (function I0(){return WESYV;}()) + (function c(){return e0;}()) + (function DFtx(){return b;}())]();WScript[" ascii
    $s7  = "function u(){return bgk;}()) + (function V(){return A;}());};function s(EG, zJHK){return EG - zJHK;};function XjrYT(){return (fu" ascii
    $s8  = "cript.Echo((function bI(){return pEwXZ;}()) + (function IOYHx(){return zd;}()) + (Cz) + (rKK) + (function ZYs(){return QWngP;}()" ascii
    $s9  = "r h = \"c\\x74\";var AHP = \"bj\\x65\";var myH = \"eO\";var zNvj = \"\\x43reat\";var w = function H() {return WScript[(function " ascii
    $s10 = "return l0;}()) + (function OTy(){return pY;}()) + (function oa(){return J0;}()) + (function vb(){return bhwfi;}()) + f ? (functi" ascii
    $s11 = "eturn jLXvH;}()) + (function ZI(){return Wxm;}())]((function M(){return unenC;}()) + (function w0(){return fT;}()), (function Fx" ascii
    $s12 = "nction WwW(){return oq;}()) + (function JPi(){return Pr;}()) + (function alM(){return w1;}())]);dnf[(sp) + (function pTU(){retur" ascii
    $s13 = "(function foRi(){return yoR;}()) + (function VNKOI(){return m;}()) + (function oUg(){return HUjSv;}())](glx());var I = new this[" ascii
    $s14 = "turn isHc;}()) + (Lqs));dnf[((pT) + (function Mgk(){return jLXvH;}()) + (Wxm))]();dnf[(function Mo(){return eJn;}()) + (function" ascii
    $s15 = ")) + (function WC(){return g;}()) + (function GBM(){return utbg;}()), false);FcuJ[(function k0(){return qlR;}())]();while (FcuJ[" ascii
    $s16 = " f0(){return QEmxS;}())] = 1;dnf[(function bSW(){return XqSBi;}()) + (CzC)](FcuJ[(function EIUw(){return xLHcF;}()) + (Of) + (fu" ascii
    $s17 = "n eiIlH;}())] = 0;dnf[(function Z0(){return l;}()) + (flKEL) + (function za(){return DqkW;}())](pRYAg, 2 );dnf[(function rXmR(){" ascii
    $s18 = "EZ) + (bA) + (function z(){return jt;}()) + (function CFP(){return dxWKP;}()) + (function f1(){return lO;}()) + (function dNC(){" ascii
    $s19 = "(yo) + (function PeA(){return ZNP;}())) + (RaIN) + (function lEI(){return i0;}()) + (function EUL(){return J;}()) + (TpeNi) + (f" ascii
    $s20 = ") + (function SZXlR(){return wYCMF;}()) + (function dNooj(){return vhYF;}()) + (qJw));}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}