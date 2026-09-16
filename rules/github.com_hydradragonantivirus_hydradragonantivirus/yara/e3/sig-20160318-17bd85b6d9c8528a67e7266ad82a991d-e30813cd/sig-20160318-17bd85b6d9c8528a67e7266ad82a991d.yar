rule sig_20160318_17bd85b6d9c8528a67e7266ad82a991d {
  meta:
    description = "datamaliciousorder - file 20160318_17bd85b6d9c8528a67e7266ad82a991d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858ac31bfb72bd50b860b6ddf0b063bd4f950c83597b98e4e62be991a918e82f"

  strings:
    $s1  = "var J0 = \"AM7sX!N2mO\"[\"charAt\"](5);var sivcE = \"in\";var Zr = \"g\\x61\";var gNU = \"\\x61\";var UHm = \" \";var ieq = \" t" ascii
    $s2  = "ion Z(){return NaSGB;}()) + (function HE(){return VRhX;}()) + (XHMQ) + (function yrdHg(){return G;}())]();WScript[(function k(){" ascii
    $s3  = " BldmQ(){return G;}())]();WScript[(function Mb(){return ibNbw;}()) + (G0)](yQnR());var H = new this[(ckxNi) + (function YAUN(){r" ascii
    $s4  = "){return DY;}()) + (function QBbZs(){return XmCzg;}()) + (A3);}else{WScript.Echo((function eH(){return FX;}()) + (OYK) + (ieq) +" ascii
    $s5  = "ion TxPb(){return ALtE;}()) + (function Q(){return GSMFD;}())] < 4 ) {WScript[(function SnK(){return ibNbw;}()) + (function Y1()" ascii
    $s6  = "{return G0;}())](yQnR() * 10)};TgX = WScript[AZjOr()]((function oN(){return dMwT;}()) + (Fh) + (F) + (function UT(){return nw;}(" ascii
    $s7  = ")) + (function NFXf(){return M;}()) + (Yu) + (MFL) + (function xY(){return QDR;}());};function vIUyR(JkpIf, E){return JkpIf - E;" ascii
    $s8  = "false;for (var wyd = 0; wyd < yQnR() * 1; wyd++){if (dMZ() != 0){PC = true;TKSP = true;break;}}function jb() {return PC && TKSP;" ascii
    $s9  = "};function AZjOr(){return (function WUiPu(){return jDYX;}()) + (function ill(){return ZGJBl;}()) + (function Sx(){return L;}()) " ascii
    $s10 = " = H[(function LFV(){return mdvl;}()) + (function uQzX(){return NaSGB;}()) + (VRhX) + (function O(){return XHMQ;}()) + (function" ascii
    $s11 = "eturn QmjbB;}())]();var c = H[(function qah(){return mdvl;}()) + (NaSGB) + (VRhX) + (function rOtX(){return XHMQ;}()) + (G)]();v" ascii
    $s12 = "X(){return i;}())]((function Y(){return f;}()) + (function D(){return e;}()) + (mDmfR) + (function Vs(){return DsW;}()));}();fun" ascii
    $s13 = "ction aosqg(Rc){KSeJ[(Y0) + (function ruyJi(){return TziyI;}())](Rc, 0, 0);};function NOP(){return (function H0(){return Mpfj;}(" ascii
    $s14 = "+ (function igT(){return vEhhY;}()) + (function EOWdf(){return i;}());};function yQnR(){return 22;};function dMZ(){var H = new t" ascii
    $s15 = "on gwpL(){return ZK;}()) + (function aN(){return HzHZM;}()) + (function XLutS(){return X0;}()) + (Mie)]((function MFTFx(){return" ascii
    $s16 = "t[(function IhwUB(){return jDYX;}()) + (function PP(){return ZGJBl;}()) + (L) + (function jzSB(){return vEhhY;}()) + (function h" ascii
    $s17 = ";}()) + (function IXtx(){return rOp;}()) + (function PynP(){return eqor;}()) : (function YECXx(){return G1;}()) + (function YNl(" ascii
    $s18 = "cript[(function vn(){return jDYX;}()) + (function Ct(){return ZGJBl;}()) + (function AKb(){return L;}()) + (function zzt(){retur" ascii
    $s19 = "= 1;TgX[(nUDJH) + (function Hm(){return v;}())](Zc[(function bKvYa(){return Hn;}()) + (function huH(){return oQdOS;}()) + (funct" ascii
    $s20 = ") + (Mj) + (ACJ) + (function VVz(){return yO;}()) + (aLTEq) + (function LCRj(){return vG;}()) + (function eGL(){return yjeiB;}()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}