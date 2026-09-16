rule sig_20160318_8bab5909d60a779ca83c46c5bad74284 {
  meta:
    description = "datamaliciousorder - file 20160318_8bab5909d60a779ca83c46c5bad74284.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d96ad9fe9fa594c0c245314ab11d41fd3d3fe967cea800687dded2382e3c21d"

  strings:
    $x1  = "var D0 = \"a\\x69\\x6e!\";var kTg = \"y ag\";var acr = \"\\x65, tr\";var Se = \"\\x61s\";var lp = \"aEeOW\"[\"charAt\"](2);var x" ascii
    $s2  = "0;}()) + (function bC(){return UD;}()) : (function z0(){return p;}()) + (function u0(){return opoG;}()) + (djbdj);}else{WScript." ascii
    $s3  = "){return M;}()) + (H) + (function ujUE(){return oT;}()) + (RzR)]();WScript[(function TI(){return zcqUr;}()) + (function WXD(){re" ascii
    $s4  = "var V = \"C\\x72e\";var mcMO = function yYIWM() {return WScript[(function ZbrHy(){return V;}()) + (dL) + (function wOHDG(){retur" ascii
    $s5  = "O) + (function cpXwr(){return rZR;}()) + (function gXU(){return zz;}()); BZ = i(); m = WScript[(function V0(){return V;}()) + (f" ascii
    $s6  = "eturn g;}())](qjfe() * 10)};nyiIx = WScript[LsrpQ()]((function quI(){return zAoFC;}()) + (function N(){return uO;}()) + (dO) + (" ascii
    $s7  = "urn M;}()) + (function oRcm(){return H;}()) + (function rmXG(){return oT;}()) + (function U(){return RzR;}())]();WScript[(functi" ascii
    $s8  = "turn MyH;}()) + (VOoSa) + (function I0(){return vgWZL;}())] < 4 ) {WScript[(function xxN(){return zcqUr;}()) + (function YYG(){r" ascii
    $s9  = "txe){return DOrR - Atxe;};function LsrpQ(){return (function CL(){return V;}()) + (function LIG(){return dL;}()) + (koSl);};funct" ascii
    $s10 = "{MXLlZ = true;Qnz = true;break;}}function t() {return MXLlZ && Qnz;};if (t()){AWPx = mcMO[(function tpydU(){return lgdiw;}()) + " ascii
    $s11 = "turn g;}())](qjfe());var C = new this[(function XDlQj(){return uf;}())]();var NwE = C[(Vl) + (function ectl(){return M;}()) + (f" ascii
    $s12 = "unction OMez(){return dL;}()) + (function Mukjt(){return koSl;}())](BZ);m[(QD)]((S0), (function itD(){return Y;}()) + (function " ascii
    $s13 = "tion fDemX(tyUzS){mcMO[(function eHqL(){return PI;}())](tyUzS, 0, 0);};function i(){return (function Hhb(){return xo;}()) + (fun" ascii
    $s14 = "return rj;}()) + (function TXXG(){return G2;}()) + (O0) + (hm) + (function z(){return OkKWY;}()) + (JDDGg) + (function BBd(){ret" ascii
    $s15 = "eturn IyQH;}())]);nyiIx[(function tytH(){return l;}()) + (function TDxVZ(){return frwIo;}()) + (function uDK(){return lKKaf;}())" ascii
    $s16 = "(m[(Y1) + (function sa(){return arF;}()) + (function V2(){return Y2;}()) + (function G1(){return XwQdP;}()) + (function sQlp(){r" ascii
    $s17 = "oSl;}())]((function MFKGw(){return OwVx;}()) + (function TE(){return o;}()) + (AeCqV) + (function Q(){return lDCT;}()));}();func" ascii
    $s18 = "X);return ANX(ZpaQl, JbEcr);}var MXLlZ = false;var Qnz = false;for (var YYvwC = 0; YYvwC < qjfe() * 1; YYvwC++){if (FTIL() != 0)" ascii
    $s19 = "ion qjfe(){return 22;};function FTIL(){var C = new this[(uf)]();var btW = C[(function xBu(){return Vl;}()) + (function bbv(){ret" ascii
    $s20 = "())) + (fya) + (function Srn(){return mBWqx;}()) + (R) + (function jcYku(){return fP;}()) + (function Py(){return nneLc;}()) + (" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}