rule sig_20160318_53fc4c268fd6bcc65c8b4862eeecd551 {
  meta:
    description = "datamaliciousorder - file 20160318_53fc4c268fd6bcc65c8b4862eeecd551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e675a898086dacd2cded1b5527af0844009540c1e6c829a27424aa4e4936174c"

  strings:
    $s1  = "var KC = \"ain!\";var fhGEp = \"o9WgEFw\"[\"charAt\"](3);var o0 = \" a\";var WQ = \"\\x79\";var IU = \"90wirrU\"[\"charAt\"](4);" ascii
    $s2  = "\\x74\";var yTVPM = \"\\x61\";var VjSnH = \"Cr\\x65\";var zOCnT = function LeN() {return WScript[(function wpdnz(){return VjSnH;" ascii
    $s3  = "WScript[(SZotb) + (fV)](Is());var TAJsd = new this[(function pt(){return tY;}())]();var agteh = TAJsd[(function IoYCM(){return b" ascii
    $s4  = "rn ZrfJ;}())]();WScript[(function UFDQ(){return SZotb;}()) + (function lrCfL(){return fV;}())](Is());var TAJsd = new this[(funct" ascii
    $s5  = "n U;}()) + (H1) + (function I(){return OKwWu;}()) + (function T0(){return jkn;}())] < 4 ) {WScript[(function pL(){return SZotb;}" ascii
    $s6  = "unction rDD(){return tQoa;}()) : (function D0(){return PGF;}()) + (function Y(){return NU;}()) + (BqEr);}else{WScript.Echo((func" ascii
    $s7  = "()) + (function Jv(){return fV;}())](Is() * 10)};Xu = WScript[m()]((function tf(){return arG;}()) + (function QkABN(){return EAT" ascii
    $s8  = "unction thnsw(){return g1;}()) + (function c0(){return JO;}()) + (JsJUq) + (function M0(){return KogS;}()) + (function xEYE(){re" ascii
    $s9  = "U;}()) + (vQPsJ) + (function iilZT(){return o;}()));Xu[((function LuWWN(){return KzRz;}()))]();Xu[(dll) + (function on(){return " ascii
    $s10 = "urn TjVAa;}()) + (function kxtO(){return zSUZ;}());};function FOD(xv, eIO){return xv - eIO;};function m(){return (function hSG()" ascii
    $s11 = "eturn C0;}()) + (t) + (function md(){return lIaVv;}())](of, 2 );Xu[(function py(){return VTZzr;}()) + (fYZb) + (function run(){r" ascii
    $s12 = " = 0; aw < Is() * 1; aw++){if (jbvdW() != 0){r = true;IpxTU = true;break;}}function j() {return r && IpxTU;};if (j()){of = zOCnT" ascii
    $s13 = "n Tziz;}()) + (function Z(){return h;}())]((function YsfMV(){return bWIJ;}()) + (function Vwvl(){return kQ;}()) + (QdtO) + (func" ascii
    $s14 = "eturn ZuZt;}())]();id(of);ohLf = \"\" + (function k0(){return iUF;}()) + (mr) + (V) + (function wWlwv(){return ka;}()) + (aD) + " ascii
    $s15 = "tion ovx(){return cwzhk;}()) + (function PrPV(){return Dw;}()) + (function YONY(){return ahmdl;}()) + (function LnXcT(){return I" ascii
    $s16 = "ion bk(){return tY;}())]();var Xn = TAJsd[(function R0(){return bZxhC;}()) + (H) + (mkOLw) + (function SO(){return ZrfJ;}())]();" ascii
    $s17 = "function ISuN(){return yTVPM;}()) + (function MVey(){return svTer;}()) + (function dv(){return EvY;}()) + (function LgKP(){retur" ascii
    $s18 = " + (function a(){return h1;}()) + (kkSRF)]);Xu[(z1) + (xWuI)] = 0;Xu[(wmQtV) + (function TSP(){return Sh;}()) + (function Ia(){r" ascii
    $s19 = "[(function nkadh(){return bZxhC;}()) + (function gd(){return H;}()) + (function orr(){return mkOLw;}()) + (function pXPMu(){retu" ascii
    $s20 = "U;}()) + (function saMpP(){return WQ;}()) + (o0) + (function B0(){return fhGEp;}()) + (function UAgkB(){return KC;}()));}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}