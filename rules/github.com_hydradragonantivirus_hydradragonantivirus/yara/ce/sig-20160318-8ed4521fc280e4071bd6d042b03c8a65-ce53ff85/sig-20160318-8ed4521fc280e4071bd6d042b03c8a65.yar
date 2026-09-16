rule sig_20160318_8ed4521fc280e4071bd6d042b03c8a65 {
  meta:
    description = "datamaliciousorder - file 20160318_8ed4521fc280e4071bd6d042b03c8a65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef9cc8b616f60f43399e95463338e8a15184785f4cd69b5d941bd9444e058ae0"

  strings:
    $x1  = "var gn = \"ain!\";var Nk = \"ag\";var eh = \"ry \";var oTWQ = \"se,\\x20t\";var ndbE = \"N7PMoadMou\"[\"charAt\"](5);var tka = " ascii
    $s2  = " - VyLS;};function UVjkb(){return (neLU) + (function Bing(){return Y;}()) + (function oKO(){return huZYv;}()) + (function xXgK()" ascii
    $s3  = " \"Cr\";var e = function rIrUO() {return WScript[(function R(){return neLU;}()) + (function kRwWy(){return Y;}()) + (function QU" ascii
    $s4  = "return Saqv;}()) + (z) + (function LGs(){return QSJLW;}()); OZGWw = ml(); QWpv = WScript[(function tHFG(){return neLU;}()) + (fu" ascii
    $s5  = "MLAk) + (function eLJA(){return wq;}()) + (function eo(){return pun;}());}else{WScript.Echo((tka) + (function p0(){return ndbE;}" ascii
    $s6  = "eturn UHuW;}())] < 4 ) {WScript[(function Uu(){return uS;}())](OIMVC() * 10)};is = WScript[UVjkb()]((function XLkT(){return lIBT" ascii
    $s7  = "; ahU < OIMVC() * 1; ahU++){if (yNu() != 0){WuTen = true;lJG = true;break;}}function gxUjd() {return WuTen && lJG;};if (gxUjd())" ascii
    $s8  = "urn IvT;}())]();WScript[(function mSli(){return uS;}())](OIMVC());var QJp = new this[(function lf(){return w;}())]();var qIrq = " ascii
    $s9  = "eturn IvT;}())]();WScript[(function IPhTQ(){return uS;}())](OIMVC());var QJp = new this[(w)]();var k = QJp[(function wPKOH(){ret" ascii
    $s10 = ");}();function rrSNq(OQwF){e[(SU)](OQwF, 0, 0);};function ml(){return (function Fa(){return bUm;}()) + (HcjA) + (ehoR) + (functi" ascii
    $s11 = "())]);is[(function esyB(){return E0;}()) + (function JJBC(){return qg;}()) + (function Tqd(){return d0;}()) + (function yqu(){re" ascii
    $s12 = "rn UnQt;}()) + (function v(){return nT;}()) + (function p(){return hak;}()) + (function qqwNU(){return E;}()) + (function x1(){r" ascii
    $s13 = "()) + (oTWQ) + (eh) + (function sxpl(){return Nk;}()) + (function XkpoQ(){return gn;}()));}" fullword ascii
    $s14 = "FS, 2 );is[(function xedm(){return t0;}()) + (function i(){return nH;}()) + (function UiT(){return dD;}())]();rrSNq(UPeFS);W = " ascii
    $s15 = "nction KrGU(){return rZvxv;}()), (function hBzN(){return hoif;}()) + (s0) + (CgTj) + (function IGAxW(){return OeO;}()) + (POs) +" ascii
    $s16 = "ion WRa(){return ofzUp;}()) + (function nnbig(){return lW;}()) + (function Vr(){return ZieKM;}()) + (function f(){return Y0;}())" ascii
    $s17 = "{UPeFS = e[(function x(){return tHzux;}()) + (function rd(){return gFAkm;}()) + (Z0) + (function IgcBO(){return MAKpw;}()) + (fu" ascii
    $s18 = "nction XxC(){return k0;}()) + (function Pmmx(){return KHg;}()) + (function BscU(){return veh;}()) + (function t(){return vUxwL;}" ascii
    $s19 = "urn dIzU;}()) + (function Za(){return FLzVw;}()) + (function dHWmt(){return fC;}()) + (function gjkE(){return IvT;}())]();var W " ascii
    $s20 = "\" + (function OvE(){return u;}()) + (function kle(){return zNV;}()) + (PGMQu) + (function mrLX(){return S0;}()) + (function ZTm" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}