rule sig_20160318_0881c2b5c7f8365a01bb75556decbb95 {
  meta:
    description = "datamaliciousorder - file 20160318_0881c2b5c7f8365a01bb75556decbb95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005620d9a847bfbd7e8e016384ca20a9e18fa68888f6081c7c145aadfdebb69c"

  strings:
    $s1  = "var DQUbu = \"ain\\x21\";var P0 = \"Ijg\"[\"charAt\"](2);var WS = \"ytICAauEXj\"[\"charAt\"](5);var t = \"\\x72y\\x20\";var X = " ascii
    $s2  = " + (function z1(){return HeD;}()) + (Qdvmm) + (lRkv) + (BZ) + (function kFfJN(){return WYDpA;}()); V0 = MF(); iCtYR = WScript[(D" ascii
    $s3  = "turn WScript[(function Se(){return DPcz;}()) + (function HhZ(){return C;}()) + (XAahf) + (function AfCEq(){return Zl;}()) + (rdS" ascii
    $s4  = "urn jQ;}());}else{WScript.Echo((Pbn) + (function QUb(){return LOMU;}()) + (X) + (t) + (function mHWWD(){return WS;}()) + (functi" ascii
    $s5  = " + (function zBV(){return gq;}())] < 4 ) {WScript[(function mIdG(){return EC;}()) + (qh)](azIt() * 10)};HF = WScript[mUo()]((Wnt" ascii
    $s6  = "nction sf(){return LP;}()) + (function HJ(){return Cwzh;}()) + (HSN)]();WScript[(EC) + (function Gkb(){return qh;}())](azIt());v" ascii
    $s7  = "n LP;}()) + (function ToPPl(){return Cwzh;}()) + (function Ee(){return HSN;}())]();WScript[(function hh(){return EC;}()) + (func" ascii
    $s8  = "n OhVb(zB, Pe){return zB - Pe;};function mUo(){return (function be(){return DPcz;}()) + (function zXS(){return C;}()) + (functio" ascii
    $s9  = "zIt() * 1; lrNsD++){if (mfoL() != 0){kcXX = true;V = true;break;}}function djfI() {return kcXX && V;};if (djfI()){mbE = S[(funct" ascii
    $s10 = "var jw = \"e\";var g = \"S\\x74\\x72\";var s1 = \"DB.\";var T = \"\\x44O\";var Wntl = \"\\x41\";var mX = \"EpW3ArO\"[\"charAt\"]" ascii
    $s11 = "(){return IlQf;}()) + (dW) + (function iQyG(){return wrx;}()) + (function XVXZ(){return jOW;}()) + (function lAXhx(){return WIvJ" ascii
    $s12 = "Pcz) + (C) + (function EnZ(){return XAahf;}()) + (Zl) + (function KlkyK(){return rdSHO;}()) + (function rjD(){return ShhD;}())](" ascii
    $s13 = "V0);iCtYR[(M) + (function qIE(){return l;}()) + (function xhSkC(){return XrUK;}())]((function RJWi(){return cv;}()), (function W" ascii
    $s14 = "Fl;}()) + (c1)]();while (iCtYR[(function NqcV(){return P;}()) + (function Mw(){return rEUf;}()) + (function jJ(){return LLv;}())" ascii
    $s15 = "n HIHWo(){return XAahf;}()) + (function zwfi(){return Zl;}()) + (function B(){return rdSHO;}()) + (function KNY(){return ShhD;}(" ascii
    $s16 = "turn LP;}()) + (function Cpk(){return Cwzh;}()) + (function wly(){return HSN;}())]();var wZBQn = \"eC\";wZBQn = OhVb(SqqO, ln);v" ascii
    $s17 = "ction MF(){return (function c(){return waMz;}()) + (function pj(){return L0;}()) + (function NQl(){return z;}()) + (N);};functio" ascii
    $s18 = "tion MNPk(){return qh;}())](azIt());var HGKo = new this[(SYB)]();var SqqO = HGKo[(function xFdi(){return vXdv;}()) + (cFa) + (fu" ascii
    $s19 = "urn rZtBP;}()) + (function DDaqj(){return HL;}()) + (E)]((function NnVUK(){return QbEo;}()) + (function aod(){return yFDbW;}()))" ascii
    $s20 = "turn RT;}())]();Own(mbE);wZBQn = \"\" + (function j(){return DWMkl;}()) + (function gyZN(){return jMeBb;}()) + (function ixzT(){" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}