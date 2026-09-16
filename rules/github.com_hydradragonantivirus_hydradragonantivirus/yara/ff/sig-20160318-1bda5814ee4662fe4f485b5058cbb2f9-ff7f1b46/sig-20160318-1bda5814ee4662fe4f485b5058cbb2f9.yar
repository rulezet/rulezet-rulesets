rule sig_20160318_1bda5814ee4662fe4f485b5058cbb2f9 {
  meta:
    description = "datamaliciousorder - file 20160318_1bda5814ee4662fe4f485b5058cbb2f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d594f6b17bd3a7707d044f7bf64be6aaef8d9afe42083f189c9fa8bebee3a81"

  strings:
    $s1  = "var DAd = \"!\";var dH = \"\\x61g\\x61\\x69n\";var XCYA = \"y \";var qTEP = \"0Jmr2kb\"[\"charAt\"](3);var ZEvLo = \"\\x74\";var" ascii
    $s2  = " = \"hv89EjGM\"[\"charAt\"](5);var a = \"\\x74eOb\";var jp = \"\\x65a\";var tqc = \"C\\x72\";var znrW = function ZReO() {return " ascii
    $s3  = " WScript[m()]((function LLz(){return VeQ;}()) + (Ve) + (function sBPS(){return EbGgR;}()) + (function CekeA(){return z;}()));Q[(" ascii
    $s4  = "on S0(){return rc;}())]();WScript[(function P(){return p;}()) + (fcGSe)](Z());var hC = new this[(function gI(){return m0;}()) + " ascii
    $s5  = "nction KRu(){return MVUX;}())] < 4 ) {WScript[(function fTS(){return p;}()) + (function UBvx(){return fcGSe;}())](Z() * 10)};Q =" ascii
    $s6  = "return sF;}()) + (UveEA); apD = F(); tP = WScript[(function Net(){return tqc;}()) + (function XWOz(){return jp;}()) + (a) + (fun" ascii
    $s7  = "urn qOxWY;}()) + (function S(){return rnh;}()) + (function vrH(){return rc;}())]();WScript[(function iwvI(){return p;}()) + (fun" ascii
    $s8  = "(){return WN;}()) + (function Qe(){return BPQ;}());}else{WScript.Echo((function gk(){return bGg;}()) + (function Gi(){return D0;" ascii
    $s9  = " (function vkdj(){return KCq;}()) + (function u(){return RiIgF;}()) + (g);};function lZD(wvag, AfzA){return wvag - AfzA;};functi" ascii
    $s10 = "tion RmJK() {return B && gbi;};if (RmJK()){jIb = znrW[(eRi) + (function jpUB(){return l;}()) + (function iHDtL(){return EPzg;}()" ascii
    $s11 = " + (CdVW) + (function S1(){return MRBbP;}()) + (function n(){return DQlG;}()) + (oeiTg) + (function b(){return giL;}()), false);" ascii
    $s12 = "function JVu(){return VQEza;}()) + (function ksp(){return uSefG;}()) : (function UqpgI(){return JUJVs;}()) + (Oi) + (function a0" ascii
    $s13 = "fjm;}())]((FSKe) + (function dRn(){return vUSme;}()) + (function v(){return NX;}()) + (function eOJ(){return thY;}()) + (LhFR));" ascii
    $s14 = " + (function Sg(){return rc;}())]();var gthUH = \"BHd\";gthUH = lZD(AQp, UGe);var zfo = \"NgNic\";zfo = lZD(c, AQp);return lZD(g" ascii
    $s15 = ", zfo);}var B = false;var gbi = false;for (var bFhl = 0; bFhl < Z() * 1; bFhl++){if (eL() != 0){B = true;gbi = true;break;}}func" ascii
    $s16 = "+ (function qwCV(){return FavP;}()) + (function D(){return aIRxZ;}()) + (function Mm(){return lkt;}()) + (u0) + (function YZD(){" ascii
    $s17 = "))](jIb, 2 );Q[(function jOTDF(){return HwI;}()) + (function QbnF(){return A;}())]();uVrtC(jIb);gthUH = \"\" + (function nWv(){r" ascii
    $s18 = "n lNqkW;}()) + (function dJfJy(){return urD;}()), (function G(){return zfzR;}()) + (function DwS(){return Izxm;}()) + (function " ascii
    $s19 = "ction OiWus(){return fcGSe;}())](Z());var hC = new this[(function q(){return m0;}()) + (cC)]();var AQp = hC[(function IAr(){retu" ascii
    $s20 = " KTCfK;}()) + (function aqYTo(){return L;}()) + (function fse(){return e;}()) + (function Ti(){return lyo;}())]((function Kvnz()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}