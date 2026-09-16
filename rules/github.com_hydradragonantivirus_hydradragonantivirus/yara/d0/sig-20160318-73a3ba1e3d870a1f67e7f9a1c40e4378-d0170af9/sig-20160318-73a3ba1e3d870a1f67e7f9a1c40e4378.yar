rule sig_20160318_73a3ba1e3d870a1f67e7f9a1c40e4378 {
  meta:
    description = "datamaliciousorder - file 20160318_73a3ba1e3d870a1f67e7f9a1c40e4378.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "725f7bfc1a1b2d8090867e7d8dccc9bfe085ef05d0ec9446dfc796450e6b7acb"

  strings:
    $x1  = "var tgX = \"7!LT\"[\"charAt\"](1);var Hza = \"\\x6e\";var MyP = \"g\\x61i\";var n = \"dfPas\"[\"charAt\"](3);var t = \"ry \";var" ascii
    $s2  = "A;}()) + (function IrCqC(){return x;}()) + (eHkw) + (function ii(){return fcf;}())]();WScript[(eY) + (function HLKN(){return WoW" ascii
    $s3  = "); cwucj = WScript[(function jkYZN(){return aUzG;}()) + (ZUxP) + (function AWo(){return we;}()) + (function peNI(){return DB;}()" ascii
    $s4  = "WScript[VgKG()]((function vjy(){return jlMTh;}()) + (tHAO) + (function nrS(){return qh;}()) + (function LRS(){return Im;}()));QX" ascii
    $s5  = "() {return WScript[(function rnl(){return aUzG;}()) + (function vf(){return ZUxP;}()) + (function BXs(){return we;}()) + (functi" ascii
    $s6  = "))]();WScript[(function RvOpQ(){return eY;}()) + (function mHpc(){return WoW;}()) + (function OMfub(){return q;}())](MPe());var " ascii
    $s7  = "));}else{WScript.Echo((aqC) + (kCz) + (function t0(){return BBPuI;}()) + (function Jg(){return OY;}()) + (function Zu(){return t" ascii
    $s8  = "Y(){return wUjKa;}())] < 4 ) {WScript[(eY) + (function mLj(){return WoW;}()) + (function Om(){return q;}())](MPe() * 10)};QXh = " ascii
    $s9  = "ction cGjv(ZjZP, UFu){return ZjZP - UFu;};function VgKG(){return (aUzG) + (function TNm(){return ZUxP;}()) + (function Ov(){retu" ascii
    $s10 = "(var ja = 0; ja < MPe() * 1; ja++){if (oPUaw() != 0){s = true;tcWS = true;break;}}function Mpt() {return s && tcWS;};if (Mpt()){" ascii
    $s11 = "rn we;}()) + (DB) + (function XXIbu(){return g;}());};function MPe(){return 22;};function oPUaw(){var nXSQj = new this[(Tw)]();v" ascii
    $s12 = ") + (function CcVA(){return JTQ;}()) + (function d(){return RJWXH;}()) + (function YmLXe(){return JBIjW;}()));}();function Tl(XO" ascii
    $s13 = "tion GL(){return fsN;}()) + (function HnBJR(){return WstaA;}()) + (function k(){return qRg;}()) + (function g2(){return PYg;}())" ascii
    $s14 = "tion CgJ(){return VPOA;}()) + (function iiy(){return x;}()) + (function Vy(){return eHkw;}()) + (function yT(){return fcf;}())](" ascii
    $s15 = "f){Kp[(function eMskU(){return sp;}()) + (function Y(){return POOge;}())](XOf, 0, 0);};function nC(){return (function TYr(){retu" ascii
    $s16 = "ar UBAgq = nXSQj[(eNN) + (VPOA) + (function dlv(){return x;}()) + (function CBe(){return eHkw;}()) + (function a(){return fcf;}(" ascii
    $s17 = "unction W(){return deK;}())) + (function DHaR(){return W0;}()) + (function NWojq(){return rakIe;}()) + (function AL(){return Eyr" ascii
    $s18 = "cj[(function gaTC(){return Q;}())]();while (cwucj[(function h(){return vTUY;}()) + (function QG(){return ffg;}()) + (function wE" ascii
    $s19 = "+ (function hm(){return WYW;}()) + (function KrBt(){return z;}()) + (function w(){return g1;}()) + (function O0(){return yvNA;}(" ascii
    $s20 = "nXSQj = new this[(function rok(){return Tw;}())]();var CXW = nXSQj[(function kCyY(){return eNN;}()) + (function pUD(){return VPO" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}