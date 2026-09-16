rule sig_20160318_29388ca6182fc7ce071ae15ac562d7a7 {
  meta:
    description = "datamaliciousorder - file 20160318_29388ca6182fc7ce071ae15ac562d7a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa1d5b7d2d79077218acb7ad8640eec2fd8c78c9def4d32fae42c672c81305e"

  strings:
    $x1  = "var sR = \"in!\";var Rq0 = \"aga\";var xgr = \"\\x72y \";var gO = \"t\";var oi = \"se,\\x20\";var ORPAy = \"ea\";var cI = \"Pl\"" ascii
    $s2  = "gR = \"i\";var Y1 = \"ip\\x4by\";var Y0 = \"NAc/z\"[\"charAt\"](3);var i1 = \"TEMP%\";var sc = \"%\";var Cjp = \"ng\\x73\";var v" ascii
    $s3  = " h = \"\\x74e\";var iJWij = \"\\x72ea\";var qAO = \"C\";var AOX = function tnUd() {return WScript[(qAO) + (function I(){return i" ascii
    $s4  = "()) + (function Rwkri(){return B;}())]();WScript[(function G0(){return NxR;}()) + (function wlW(){return jQgL;}())](f());var acC" ascii
    $s5  = "pt[(function GF(){return NxR;}()) + (function C(){return jQgL;}())](f() * 10)};J = WScript[F()]((function zFdP(){return XDend;}(" ascii
    $s6  = "p(){return AWAmH;}()) + (function JI(){return olb;}()); vjO = SxMwL(); dmL = WScript[(qAO) + (iJWij) + (function oymsv(){return " ascii
    $s7  = "eturn F0;}()) + (function Ytspy(){return f1;}()) + (function eXqG(){return J2;}()) + (VUcgF) + (function fVwyN(){return Z;}()) +" ascii
    $s8  = "r(){return km;}()) + (CYOK);};function lzz(QjjJM, VpW){return QjjJM - VpW;};function F(){return (function arR(){return qAO;}()) " ascii
    $s9  = "() {return CZ && b;};if (GP()){OJByG = AOX[(function QZdZI(){return Ov;}()) + (function TUD(){return l;}()) + (GEv) + (function " ascii
    $s10 = "ript.Echo((function ZE(){return cI;}()) + (ORPAy) + (function MCR(){return oi;}()) + (function bW(){return gO;}()) + (xgr) + (Rq" ascii
    $s11 = "OGph\"[\"charAt\"](2);var olb = \"ex\\x65\";var AWAmH = \".\";var OBEx = \"qLtso\";var O = \"Q5g\";var kMbr = \"2HjnzY0J\"[\"cha" ascii
    $s12 = " = new this[(v)]();var M = acC[(function s(){return CDpmi;}()) + (gpTE) + (function uf(){return Qbx;}()) + (function E(){return " ascii
    $s13 = "ion c0(){return ltdjA;}()))]();J[(kMGK)] = 1;J[(function CXQ(){return vt;}())](dmL[(function u(){return cF;}()) + (ZR) + (functi" ascii
    $s14 = "function Tj(){return xkuT;}()) + (FDUP) + (function muje(){return moD;}()) + (function o0(){return uHX;}()), false);dmL[(functio" ascii
    $s15 = "vvYr;}()) + (function QGYrz(){return lbtk;}()) + (Gd) + (function pioQ(){return a;}()) + (function PKeQL(){return B;}())]();WScr" ascii
    $s16 = "n UCbuA(){return YXwkj;}())]();while (dmL[(function CyQVD(){return WO;}()) + (odI) + (function M2(){return s0;}())] < 4 ) {WScri" ascii
    $s17 = " ? (O0) + (B0) + (TSA) + (function g(){return S;}()) : (function Zk(){return xFGG;}()) + (function Rn(){return dL;}());}else{WSc" ascii
    $s18 = ")) + (iZ) + (function Vt(){return SCr;}()) + (function WqpDd(){return PaupJ;}()));J[((function PuJuT(){return vcLC;}()) + (funct" ascii
    $s19 = "))]((function b3(){return P;}()) + (RBcmr) + (function LsHPZ(){return zvred;}()), (function Gar(){return gHSs;}()) + (function x" ascii
    $s20 = "0) + (function iX(){return sR;}()));}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}