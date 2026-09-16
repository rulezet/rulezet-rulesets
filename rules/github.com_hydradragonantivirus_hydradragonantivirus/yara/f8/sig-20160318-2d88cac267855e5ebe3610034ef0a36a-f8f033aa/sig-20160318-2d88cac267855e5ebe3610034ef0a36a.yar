rule sig_20160318_2d88cac267855e5ebe3610034ef0a36a {
  meta:
    description = "datamaliciousorder - file 20160318_2d88cac267855e5ebe3610034ef0a36a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d83f96f9e35eb1f815b67a78028a2180400124cd2a4c86f2faf682e792af47"

  strings:
    $x1  = "var rOTj = \"n!\";var D0 = \"i\";var AGX = \"\\x67a\";var OZH = \"\\x79\\x20a\";var qpTaR = \" tr\";var K0 = \"a\\x73\\x65,\";va" ascii
    $s2  = "ar n = \"\\x4fb\";var cRZJ = \"5erdeT5i\"[\"charAt\"](4);var zILsA = \"at\";var bBIQJ = \"Cre\";var q = function t() {return WSc" ascii
    $s3  = "se{WScript.Echo((function fyr(){return IZo;}()) + (function V1(){return K0;}()) + (function kBGg(){return qpTaR;}()) + (function" ascii
    $s4  = "zV(){return xOE;}()) + (AjdMP); puhPD = qd(); ni = WScript[(function mBY(){return bBIQJ;}()) + (zILsA) + (function IAj(){return " ascii
    $s5  = "ile (ni[(isB) + (hcWcz) + (function OvjD(){return mGUB;}()) + (function U(){return FKd;}())] < 4 ) {WScript[(function ro(){retur" ascii
    $s6  = "on m(){return XR;}()) + (W0) + (function Mb(){return ubXSe;}()) + (function jsF(){return bqBnu;}())]();WScript[(function EdgWI()" ascii
    $s7  = "n anwV;}()) + (function RVN(){return KwwI;}())](PWtU() * 10)};P = WScript[KPM()]((function fzcKR(){return CVt;}()) + (Tj) + (fun" ascii
    $s8  = "(){return XR;}()) + (function clJ(){return W0;}()) + (function X(){return ubXSe;}()) + (bqBnu)]();WScript[(function nuQvi(){retu" ascii
    $s9  = "mu(){return AS;}()) + (function OTgeT(){return qNrP;}()) + (function WkixU(){return mSl;}()) + (function QN(){return IQ;}());}el" ascii
    $s10 = "}()) + (function pTJ(){return Uf;}());};function qFgu(NCtT, sHKG){return NCtT - sHKG;};function KPM(){return (bBIQJ) + (function" ascii
    $s11 = "doe\";var rHXuH = \"k20oYf\"[\"charAt\"](0);var j0 = \"\\x2fl2\";var Li = \"\\x2eco\\x6d\";var WXm = \"el\";var hiAZw = \"trav\"" ascii
    $s12 = " pp;}()) + (function cBd(){return oSqw;}()) + (function vxyN(){return wIP;}()) + (function rFMoj(){return GVI;}()) + (function o" ascii
    $s13 = "ction GJmn(){return L;}()) + (function yH(){return JK;}()) + (function DpDLg(){return PgDmE;}()));P[((ZynTM) + (Vxai))]();P[(fun" ascii
    $s14 = ")) + (HvLaq) + (function aSV(){return ZuQjN;}()) + (function JA(){return VMO;}()) : (function HSu(){return qY;}()) + (function I" ascii
    $s15 = "ho;}()) + (XR) + (W0) + (function GBIl(){return ubXSe;}()) + (function Uglz(){return bqBnu;}())]();var GXc = \"AUlk\";GXc = qFgu" ascii
    $s16 = ", AiO);var V = \"VoA\";V = qFgu(kf, M);return qFgu(GXc, V);}var szRU = false;var u = false;for (var Dil = 0; Dil < PWtU() * 1; D" ascii
    $s17 = "}()) + (function ywdNn(){return pb;}()) + (NhJJW) + (ZUE) + (function VMTVk(){return XtehD;}()) + (msrg) + (function qF(){return" ascii
    $s18 = "rn anwV;}()) + (KwwI)](PWtU());var PpkbA = new this[(function cRGH(){return V0;}())]();var kf = PpkbA[(function iWrrh(){return T" ascii
    $s19 = " EweU;}()) + (function p(){return YiW;}())]((function H0(){return Er;}()) + (function D(){return f;}())) + (function yf(){return" ascii
    $s20 = " WS;}())](ni[(function VaPw(){return Fl;}()) + (function vshVy(){return x;}()) + (X0) + (function kJ(){return EPsi;}()) + (ck)])" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}