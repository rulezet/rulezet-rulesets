rule sig_20160318_029d2e6f9bcfdd77372b3abcda43ef9b {
  meta:
    description = "datamaliciousorder - file 20160318_029d2e6f9bcfdd77372b3abcda43ef9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4204a9e5ca1382a2b9e63304c5e01d422a13331c81e5bb9c09a905cadac52d00"

  strings:
    $s1  = "var jSxmN = \"in!\";var D = \" aga\";var yxe = \"y\";var xN = \"\\x65,\\x20tr\";var CENs = \"rsw\"[\"charAt\"](1);var IUJl = \"P" ascii
    $s2  = "{WScript[(function igpeS(){return DqA;}()) + (function S(){return YJBj;}()) + (function gIej(){return EDE;}()) + (function J(){r" ascii
    $s3  = "ion B1(){return quq;}())]();WScript[(function A(){return DqA;}()) + (function iEsz(){return YJBj;}()) + (function iSICe(){return" ascii
    $s4  = "eturn MPc;}())](zJBsH() * 10)};x = WScript[Ej()]((function aFOjZ(){return zxsx;}()) + (function PPhwy(){return toJWK;}()) + (YbZ" ascii
    $s5  = "n ImhK(){return s0;}()) + (rBX) + (JUXin) + (Um);}else{WScript.Echo((function QCf(){return IUJl;}()) + (function cs(){return CEN" ascii
    $s6  = " (function AuZBH(){return cGHLP;}()) + (function UwV(){return YTmEa;}()) + (quq)]();WScript[(DqA) + (YJBj) + (function hZNT(){re" ascii
    $s7  = "x63\";var rrm = \"eO\";var jD = \"at\";var rAtM = \"re\";var Hx = \"C\";var aymt = function SlT() {return WScript[(Hx) + (functi" ascii
    $s8  = "return k;}()) + (CCmLA); Kmis = QyMlW(); m = WScript[(function BivZc(){return Hx;}()) + (function R(){return rAtM;}()) + (jD) + " ascii
    $s9  = "tion Q(){return Mdqc;}());};function cK(T, G){return T - G;};function Ej(){return (Hx) + (function W(){return rAtM;}()) + (funct" ascii
    $s10 = "var ED = 0; ED < zJBsH() * 1; ED++){if (DOBAW() != 0){pvKO = true;TtaHY = true;break;}}function vfUv() {return pvKO && TtaHY;};i" ascii
    $s11 = "2\";var JUXin = \"6816\";var rBX = \"1\\x383\";var s0 = \"2\";var mxDk = \"fxd\"[\"charAt\"](0);var Hoy = \"a\\x73\\x64\";var Z " ascii
    $s12 = "nction DOBAW(){var Sc = new this[(function lGr(){return cL;}()) + (function OE(){return NsAyS;}())]();var pPRC = Sc[(B0) + (I) +" ascii
    $s13 = " EDE;}()) + (function ydKrz(){return MPc;}())](zJBsH());var Sc = new this[(cL) + (NsAyS)]();var Dj = Sc[(function dbvXl(){return" ascii
    $s14 = "nction JQ(){return yfJ;}()) + (function dNJbM(){return sgt;}())](s, 2 );x[(function VbKF(){return lrMgA;}())]();uYU(s);kDnC = \"" ascii
    $s15 = "turn EDE;}()) + (function iLjgk(){return MPc;}())](zJBsH());var Sc = new this[(function dxYd(){return cL;}()) + (function jOvEP(" ascii
    $s16 = "turn ivNRx;}()), false);m[(dNFeh)]();while (m[(tsc) + (function Wk(){return ypbL;}()) + (function inoRl(){return mb;}())] < 4 ) " ascii
    $s17 = "unction roE(){return Ei;}()) + (function O0(){return OFxqw;}()) + (function K(){return TNXJ;}()) + (dkshA) + (function Skmz(){re" ascii
    $s18 = "ion X0(){return jD;}()) + (rrm) + (function Wy(){return MPu;}()) + (function e(){return l;}());};function zJBsH(){return 22;};fu" ascii
    $s19 = " + (function KW(){return zJFxj;}()) + (function uqD(){return lGvYg;}()) + (function Th(){return U0;}()) + (function xv(){return " ascii
    $s20 = "};function QyMlW(){return (function P(){return Blh;}()) + (function zKB(){return AHtb;}()) + (function i(){return B;}()) + (func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}