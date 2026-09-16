rule sig_20160318_befe49f6246c2ea6474684eb77966ff3 {
  meta:
    description = "datamaliciousorder - file 20160318_befe49f6246c2ea6474684eb77966ff3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82eaaeccfb32631c2a8cf67512b3ba883ea647b004580d57d794d3beaef36dcd"

  strings:
    $x1  = "var IIT = \"vV7S!lZY\"[\"charAt\"](4);var CIP = \"ain\";var PeWyc = \"AjNXsgk\"[\"charAt\"](5);var KFqG = \" \\x61\";var fQ = \"" ascii
    $s2  = "Ai;}())] < 4 ) {WScript[(function kG(){return c;}())](ehj() * 10)};vrL = WScript[YH()]((function mBvG(){return IxgU;}()) + (u2) " ascii
    $s3  = ") + (w0) + (function BCWR(){return nGkL;}()) + (function zVyV(){return o;}())]();WScript[(function Xzx(){return c;}())](ehj());v" ascii
    $s4  = "uK;}()) + (function aqtCQ(){return w0;}()) + (nGkL) + (function mIX(){return o;}())]();WScript[(function kICRe(){return c;}())](" ascii
    $s5  = ") + (Gv) : (function vvDcX(){return V;}()) + (function fe(){return kUcyn;}()) + (J0);}else{WScript.Echo((function vHsFY(){return" ascii
    $s6  = " Pdz(){return VTd;}()) + (function lKScK(){return jCn;}()); CCXI = byL(); aQQVn = WScript[(function efMb(){return RYl;}()) + (fu" ascii
    $s7  = "rn is;}()) + (function l0(){return Xhjf;}());};function UKlg(dcs, pdhN){return dcs - pdhN;};function YH(){return (function oPXU(" ascii
    $s8  = "\"](4);var bVVD = \"\\x74\\x65O\\x62j\";var RYl = \"Cr\\x65a\";var Z = function Awv() {return WScript[(function CNUKE(){return R" ascii
    $s9  = "\"P\";var VqW = \"d\\x73\";var ZQ = \"con\";var RUZQ = \"lis\\x65\";var hsFXv = \"\\x6c\";var r = \"getMi\";var mAF = \"Da\\x74e" ascii
    $s10 = "rn WPyIj;}()) + (function MZVga(){return JXIY;}()) + (function BBL(){return O;}()) + (function q1(){return em;}()) + (function u" ascii
    $s11 = "F, Ty);var l = \"acKd\";l = UKlg(jq, TF);return UKlg(xebji, l);}var HFDhM = false;var Q = false;for (var q = 0; q < ehj() * 1; q" ascii
    $s12 = " mZ;}()) + (I) + (aQH) + (fQ) + (KFqG) + (function fm(){return PeWyc;}()) + (function MJUm(){return CIP;}()) + (IIT));}" fullword ascii
    $s13 = ";function byL(){return (fYd) + (bCfCK) + (function vY(){return pdqAg;}()) + (function zaA(){return toM;}()) + (function b(){retu" ascii
    $s14 = "k;}())]((function tJkB(){return vKe;}()) + (function GK(){return q0;}()) + (function uj(){return xD;}()) + (function Ngaw(){retu" ascii
    $s15 = "nction X(){return zSl;}())] = 0;vrL[(wy) + (function IOt(){return b0;}()) + (JkVX)](QH, 2 );vrL[(x) + (w1)]();zCO(QH);xebji = \"" ascii
    $s16 = " (function s(){return bVVD;}()) + (function RmIKa(){return fYmO;}()) + (function OvUw(){return w;}()) + (function sTq(){return A" ascii
    $s17 = "irS(){return EuK;}()) + (function Ai(){return w0;}()) + (nGkL) + (function pup(){return o;}())]();var xebji = \"P\";xebji = UKlg" ascii
    $s18 = "urn yRvuc;}()) + (function QkLE(){return GSjG;}()) + (function XEBb(){return K;}()) + (function p(){return vWbW;}()) + (function" ascii
    $s19 = " (function SQZXd(){return dKzU;}()) + (K0) + (function Ts(){return u0;}()) + (function d0(){return Zr;}()) + (function SmQUk(){r" ascii
    $s20 = "ar ltjGv = new this[(function YVyo(){return cJ;}())]();var TF = ltjGv[(function ax(){return vQqjW;}()) + (function Cb(){return E" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}