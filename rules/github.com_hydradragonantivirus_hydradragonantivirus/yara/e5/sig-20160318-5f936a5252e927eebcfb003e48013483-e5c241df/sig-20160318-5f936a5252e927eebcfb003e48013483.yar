rule sig_20160318_5f936a5252e927eebcfb003e48013483 {
  meta:
    description = "datamaliciousorder - file 20160318_5f936a5252e927eebcfb003e48013483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47445e5401303551d18e3aafc1e87ea14798593b5ae1abc414e61f9efa5dcb7e"

  strings:
    $s1  = "var bOnzB = \"ain!\";var bQR = \"j1rgtF\"[\"charAt\"](3);var OXhLD = \"ry a\";var zuXk = \"e,\\x20t\";var njlCH = \"s\";var rwP " ascii
    $s2  = "n v() {return WScript[(function Vh(){return Rfvk;}()) + (C) + (function ME(){return fRv;}()) + (jgJeF) + (function VO(){return A" ascii
    $s3  = "fizc(){return Jq;}()) + (W) + (function viq(){return jkHQb;}())]();WScript[(function EN(){return aJGL;}()) + (function ocQyu(){r" ascii
    $s4  = "())] < 4 ) {WScript[(function R0(){return aJGL;}()) + (function mKrMC(){return VYpFl;}())](IoBT() * 10)};fI = WScript[z()]((func" ascii
    $s5  = "j1;}()) + q ? (vfrB) + (O0) : (function pwLbM(){return QDL;}()) + (function Q1(){return bA;}()) + (xf);}else{WScript.Echo((funct" ascii
    $s6  = ")) + (function Mc(){return yy;}()) + (YVtR) + (function Fqesd(){return yqdMk;}()); UDcs = AWd(); p = WScript[(function bl(){retu" ascii
    $s7  = "){return cJpx;}()) + (function fACuX(){return zPffE;}()) + (Jq) + (function KcC(){return W;}()) + (jkHQb)]();WScript[(function H" ascii
    $s8  = "ction D0(){return qOwq;}()) + (smAU) + (function TDy(){return bpx;}());};function Aa(D, WDYhI){return D - WDYhI;};function z(){r" ascii
    $s9  = "0; WPXs < IoBT() * 1; WPXs++){if (x() != 0){q = true;Fk = true;break;}}function ZkCr() {return q && Fk;};if (ZkCr()){mS = f[(WNY" ascii
    $s10 = "hOl;}()) + (function Hf(){return qDppU;}()) + (function tpAh(){return GCKzw;}()), false);p[(VSF) + (function NRM(){return AMRO;}" ascii
    $s11 = "G = by[(function qnPlI(){return JtJT;}()) + (function gqO(){return cJpx;}()) + (function THoky(){return zPffE;}()) + (function k" ascii
    $s12 = "eturn VYpFl;}())](IoBT());var by = new this[(function sp(){return N;}()) + (rB)]();var Vq = by[(JtJT) + (cJpx) + (function E(){r" ascii
    $s13 = ")] = 1;fI[(PbW) + (Mb)](p[(function nfY(){return zKzJ;}()) + (w) + (sV) + (D1)]);fI[(function ClFLq(){return ZJD;}()) + (functio" ascii
    $s14 = "JsF(){return aJGL;}()) + (function LJ(){return VYpFl;}())](IoBT());var by = new this[(N) + (function rt(){return rB;}())]();var " ascii
    $s15 = "}())](UDcs);p[(function cyjCn(){return FJSvZ;}())]((function ETxTc(){return sFA;}()), (function IAVmj(){return cRt;}()) + (funct" ascii
    $s16 = " + (function taLIi(){return d;}()) + (function Tf(){return XGooR;}()) + (function zSwny(){return b;}()) + (function cJ(){return " ascii
    $s17 = "0;}()) + (function rr(){return oLY;}())](mS, 2 );fI[(function AL(){return gDADU;}())]();j(mS);yZK = \"\" + (function cM(){return" ascii
    $s18 = "(){var by = new this[(function FEAgH(){return N;}()) + (function CtPft(){return rB;}())]();var hV = by[(JtJT) + (function oBpKJ(" ascii
    $s19 = ")) + (function icM(){return OXhLD;}()) + (function HX(){return bQR;}()) + (function rML(){return bOnzB;}()));}" fullword ascii
    $s20 = "urn jgJeF;}()) + (function dYz(){return AFZRy;}()) + (function RcEiz(){return fxjc;}());};function IoBT(){return 22;};function x" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}