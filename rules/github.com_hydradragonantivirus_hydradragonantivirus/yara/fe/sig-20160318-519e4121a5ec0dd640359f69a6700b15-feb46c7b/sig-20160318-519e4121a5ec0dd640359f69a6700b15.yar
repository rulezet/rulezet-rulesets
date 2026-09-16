rule sig_20160318_519e4121a5ec0dd640359f69a6700b15 {
  meta:
    description = "datamaliciousorder - file 20160318_519e4121a5ec0dd640359f69a6700b15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fca4b34b7163c21eca1341f0f13039758e71dd9f169aa9e74489eb796062feef"

  strings:
    $x1  = "var lQ = \"Xr!baD\"[\"charAt\"](2);var e0 = \"aga\\x69n\";var UK = \"y \";var h = \"\\x72\";var b0 = \"e, t\";var kiw = \"Pl\\x6" ascii
    $s2  = ")};Km = WScript[HU()]((WkUk) + (Nfsg) + (function nu(){return UA;}()) + (function zFy(){return PES;}()) + (function b(){return e" ascii
    $s3  = " cuqA(){return PqqQ;}()) + (function hqYYU(){return G;}())]();WScript[(function bb(){return zCyMo;}()) + (function Ac(){return O" ascii
    $s4  = "ion XNAbU(){return fXPZo;}())] < 4 ) {WScript[(function g(){return zCyMo;}()) + (function JZmXR(){return OhOI;}())](XfPpA() * 10" ascii
    $s5  = " tPoFR() {return WScript[(function Eb(){return qKsj;}()) + (function k(){return ygJk;}()) + (function OVsM(){return KVw;}()) + (" ascii
    $s6  = "urn TpY;}()) + (function ilrOi(){return oYxN;}()) + (d); IBXx = zkDlB(); cO = WScript[(function q(){return qKsj;}()) + (function" ascii
    $s7  = "}());}else{WScript.Echo((function NhQ(){return kiw;}()) + (function n(){return b0;}()) + (function Sr(){return h;}()) + (functio" ascii
    $s8  = "cq(){return Pjjcw;}()) + (function lM(){return PqqQ;}()) + (G)]();WScript[(function zs(){return zCyMo;}()) + (OhOI)](XfPpA());va" ascii
    $s9  = "turn IdBf;}()) + (function f(){return ssxQF;}()) + (Cn);};function aO(OBa, STeEY){return OBa - STeEY;};function HU(){return (fun" ascii
    $s10 = "7\\x53\";var z = \"c\\x74\";var nIoKO = \"bokvoe4\"[\"charAt\"](5);var KVw = \"\\x65Obj\";var ygJk = \"reat\";var qKsj = \"C\";v" ascii
    $s11 = "n E0(){return UK;}()) + (function JrkAL(){return e0;}()) + (lQ));}" fullword ascii
    $s12 = "hOI;}())](XfPpA());var bweWh = new this[(function rrZF(){return Kw;}())]();var MeM = bweWh[(function FS(){return Yo;}()) + (func" ascii
    $s13 = "tion HYinx(){return BiC;}()) + (function hDpwo(){return Pjjcw;}()) + (PqqQ) + (G)]();var BSE = \"R\";BSE = aO(A, MJiVt);var vwhI" ascii
    $s14 = "{return ubpo;}())]((function U(){return qZLvg;}()) + (function AHk(){return fnQ;}())) + (function c(){return qd;}()) + (YjwNY) +" ascii
    $s15 = "(function q2(){return MQH;}())]();while (cO[(function G0(){return oqae;}()) + (bN) + (function zUfO(){return fkvqh;}()) + (funct" ascii
    $s16 = "Rh;}())] = 0;Km[(function cVOFt(){return sxjF;}()) + (function szybD(){return G1;}()) + (tSwYB)](mJc, 2 );Km[(function CzE(){ret" ascii
    $s17 = "(){return Zgxv;}()) + (Oe) + (function XSm(){return Lvqo;}())]((function gFWa(){return u0;}()), (function S(){return a;}()) + (f" ascii
    $s18 = "urn GDtlH;}()) + (KEK)]();kb(mJc);BSE = \"\" + (function lFPo(){return Ux;}()) + (function H(){return FveNT;}()) + (function FzA" ascii
    $s19 = "ction chd(){return qKsj;}()) + (ygJk) + (KVw) + (nIoKO) + (function pR(){return z;}());};function XfPpA(){return 22;};function t" ascii
    $s20 = "function jsOz(){return nIoKO;}()) + (z)]((function mqcr(){return L;}()) + (x) + (QzDk) + (i));}();function kb(wyIm){mz[(function" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}