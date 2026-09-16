rule sig_20160318_d7eaa436f8bb4757a6c24bed04adeb7a {
  meta:
    description = "datamaliciousorder - file 20160318_d7eaa436f8bb4757a6c24bed04adeb7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6548736c54e622b077dd3d09146a89f179475a69abe3f06cdc3b1203342232c9"

  strings:
    $s1  = "var VBBnB = \"\\x69\\x6e!\";var x = \"\\x20\\x61g\\x61\";var gXPv = \"\\x2c t\\x72y\";var CrUOq = \"\\x65as\\x65\";var AI = \"Pl" ascii
    $s2  = "f(){return xJF;}()) : (S0) + (Yix);}else{WScript.Echo((AI) + (CrUOq) + (function Kkzq(){return gXPv;}()) + (x) + (function QFonB" ascii
    $s3  = "turn WScript[(V) + (function T(){return MYqOp;}()) + (function R0(){return k;}()) + (function L(){return PzENN;}()) + (function " ascii
    $s4  = ";}()) + (function QX(){return Ul;}()) + (lj) + (mii) + (function zNeZZ(){return sjZX;}()); jdiGm = hsn(); ahpw = WScript[(functi" ascii
    $s5  = "n jApJ;}())]();WScript[(function Hpyuf(){return PgFS;}())](b());var eDPys = new this[(kHbNQ) + (function rU(){return n;}())]();v" ascii
    $s6  = "())] < 4 ) {WScript[(function WRt(){return PgFS;}())](b() * 10)};hVe = WScript[Krec()]((function rIrgX(){return cZMj;}()) + (fun" ascii
    $s7  = "turn LNx;}());};function Rv(FWl, yL){return FWl - yL;};function Krec(){return (function hCQ(){return V;}()) + (function xiV(){re" ascii
    $s8  = " iSCB && HQ;};if (NeST()){kpQO = s[(aMFd) + (function ro(){return Hhfz;}()) + (function Aljm(){return JFIdP;}()) + (vIE) + (func" ascii
    $s9  = "qYB(){return jApJ;}())]();WScript[(function fv(){return PgFS;}())](b());var eDPys = new this[(function tbDlu(){return kHbNQ;}())" ascii
    $s10 = "Ytg2\"[\"charAt\"](1);var PzENN = \"b\\x6aec\";var k = \"a\\x74eO\";var MYqOp = \"TYeV\"[\"charAt\"](2);var V = \"Cr\";var s = f" ascii
    $s11 = "k0(){return BtlOT;}())]((function pH(){return b0;}()) + (function UI(){return sR;}()) + (NTQSX) + (eeZZw) + (function HzSh(){ret" ascii
    $s12 = "SCB = false;var HQ = false;for (var C = 0; C < b() * 1; C++){if (H() != 0){iSCB = true;HQ = true;break;}}function NeST() {return" ascii
    $s13 = "n (function o(){return oC;}()) + (XViOW) + (function D(){return pOY;}()) + (function RraKX(){return dtvV;}()) + (function Z(){re" ascii
    $s14 = ");ODn(kpQO);ZcUG = \"\" + (function iCW(){return OF;}()) + (function s2(){return b1;}()) + (LJP) + (I) + (zR) + (function srvc()" ascii
    $s15 = ";}()) + (function Y0(){return H0;}()) + (function zh(){return EG;}())](kpQO, 2 );hVe[(sVfjT) + (function F2(){return QuEU;}())](" ascii
    $s16 = "DPys[(function FBsnI(){return F;}()) + (function e(){return PtI;}()) + (function laOHX(){return pOY0;}()) + (function rZ(){retur" ascii
    $s17 = "eturn t;}()) + (function Dt(){return NbV;}()) + (function lXSD(){return NvYi;}()) + (function Rd(){return VZQ;}()) + (AaCjh) + (" ascii
    $s18 = " b(){return 22;};function H(){var eDPys = new this[(function z(){return kHbNQ;}()) + (function iB(){return n;}())]();var UAu = e" ascii
    $s19 = "tion Gy(){return T0;}()) + (function Jfwpj(){return lW;}()) + (function nYw(){return JJW;}())]((function Q0(){return nt;}()) + (" ascii
    $s20 = "function GR(){return cre;}()) + (function IUBm(){return ZZ;}()) + iSCB ? (Ay) + (function KJeU(){return J0;}()) + (function aoiv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}