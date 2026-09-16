rule sig_20160318_bb22f2f0413909a06360828063574f1e {
  meta:
    description = "datamaliciousorder - file 20160318_bb22f2f0413909a06360828063574f1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8b5828a2d42d7265ced440d83a7b2957121a3fac83ec1d1d147899e6ae9f1d2"

  strings:
    $s1  = "var skJm = \"in!\";var Teff = \"ag\\x61\";var ki = \"try \";var dCRj = \"s\\x65,\\x20\";var UIh = \"\\x6c\\x65\\x61\";var Tao = " ascii
    $s2  = "function OLQvp(){return mLxFn;}()) + (AzWZ); K = UYkyx(); raDx = WScript[(VP) + (function oXRkx(){return u;}()) + (function gms(" ascii
    $s3  = "e) + (function Pus(){return zF;}())]();WScript[(qE) + (function rZK(){return YRijk;}())](KrGN());var Kfn = new this[(function wh" ascii
    $s4  = " + (UFlP)] < 4 ) {WScript[(function hSIZe(){return qE;}()) + (YRijk)](KrGN() * 10)};GEL = WScript[do0()]((function VD(){return P" ascii
    $s5  = "n ythqk;}()) + (function UYpP(){return Te;}()) + (zF)]();WScript[(qE) + (function IRaK(){return YRijk;}())](KrGN());var Kfn = ne" ascii
    $s6  = "{return cQDzw;}()) + (function vN(){return KdU;}()) + (m);}else{WScript.Echo((function QhVV(){return Tao;}()) + (UIh) + (functio" ascii
    $s7  = "Ob\";var u = \"\\x72\\x65\\x61\\x74e\";var VP = \"C\";var hSPDa = function lT() {return WScript[(VP) + (function ding(){return u" ascii
    $s8  = "loGMy(){return yuOz;}()), false);raDx[(cF)]();while (raDx[(function Xp(){return fOPH;}()) + (function e(){return OkYF;}()) + (J)" ascii
    $s9  = "SMZ(){return eUH;}()) + (function rBK(){return qKOm;}()) + (function EyIU(){return QoOk;}());};function NhLd(d, dxch){return d -" ascii
    $s10 = "eak;}}function ZFg() {return VXT && Z;};if (ZFg()){XF = hSPDa[(function OMfj(){return xi;}()) + (function w(){return S;}()) + (f" ascii
    $s11 = "+ (function aEn(){return xP;}()) + (function x(){return Cfe;}());};function KrGN(){return 22;};function edDq(){var Kfn = new thi" ascii
    $s12 = "urn xQ;}()) + (IQpu)] = 1;GEL[(function TckV(){return U1;}())](raDx[(function C(){return Eo;}()) + (function EeUWQ(){return IM;}" ascii
    $s13 = "()) + (qqPEi) + (function nu(){return UlT;}()) + (h)]);GEL[(function XQy(){return k0;}()) + (function CJOu(){return BOPU;}()) + " ascii
    $s14 = "w this[(function EX(){return oq;}())]();var dszq = Kfn[(function hT(){return Xvm;}()) + (function mbSbg(){return GGj;}()) + (yth" ascii
    $s15 = "DcV;}()) + (function d3(){return EnQT;}()) + (function z(){return zmrEQ;}()) + (function v(){return vSnvy;}()) + (function tZgz(" ascii
    $s16 = "(function J1(){return s0;}()) + VXT ? (function TC(){return d5;}()) + (SavfM) + (function oJQ(){return wVu;}()) : (function S0()" ascii
    $s17 = "(function XWdrC(){return bRw;}()) + (function IyC(){return ylNm;}()) + (function Y(){return EoTud;}()) + (function cVsxO(){retur" ascii
    $s18 = "urn NhLd(s, ClZR);}var VXT = false;var Z = false;for (var NR = 0; NR < KrGN() * 1; NR++){if (edDq() != 0){VXT = true;Z = true;br" ascii
    $s19 = " + (jSh)]((a), (function Z1(){return QLfDz;}()) + (function AfFzT(){return Rmb;}()) + (function X(){return TIpif;}()) + (functio" ascii
    $s20 = "(function Xf(){return r;}()) + (function DyuK(){return pzyD;}()) + (function HN(){return P;}())] = 0;GEL[(function PfB(){return " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}