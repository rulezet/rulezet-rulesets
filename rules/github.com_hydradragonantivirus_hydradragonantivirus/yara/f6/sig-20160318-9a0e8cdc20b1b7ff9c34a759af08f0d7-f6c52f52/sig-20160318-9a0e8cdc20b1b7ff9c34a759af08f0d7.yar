rule sig_20160318_9a0e8cdc20b1b7ff9c34a759af08f0d7 {
  meta:
    description = "datamaliciousorder - file 20160318_9a0e8cdc20b1b7ff9c34a759af08f0d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ea03db09b56fe05e8a93893ff429c9083dbf2d37aea31960e8cea91a3f774ca"

  strings:
    $s1  = "var YD = \"\\x6e!\";var Zww = \"\\x69\";var JwC = \"ga\";var SMrep = \" a\";var K = \"y\";var rg = \" t\\x72\";var YVuOo = \"\\x" ascii
    $s2  = ")) + (function Q(){return M;}())]();WScript[(pR) + (function mWEn(){return oVPXC;}())](cOi());var YGAxv = new this[(function xFY" ascii
    $s3  = " KUiel = \"\\x74eOb\";var Qx = \"\\x43rea\";var viYxC = function FW() {return WScript[(Qx) + (function gyy(){return KUiel;}()) +" ascii
    $s4  = "nction mrWf(){return CTq;}()) : (function BlK(){return Gj;}()) + (function FQ(){return AzTp;}());}else{WScript.Echo((function QW" ascii
    $s5  = "urn M;}())]();WScript[(function xshis(){return pR;}()) + (oVPXC)](cOi());var YGAxv = new this[(function mzIpG(){return KrW;}()) " ascii
    $s6  = "Coe(){return F0;}()) + (aEjIb) + (function YWKQu(){return XmRMG;}()) + (function MxH(){return PB;}())] < 4 ) {WScript[(function " ascii
    $s7  = "w(){return pR;}()) + (function FGD(){return oVPXC;}())](cOi() * 10)};MQphf = WScript[FqKw()]((function ADby(){return Bnx;}()) + " ascii
    $s8  = " ceqg - bEaUI;};function FqKw(){return (function lYqg(){return Qx;}()) + (function H(){return KUiel;}()) + (function Yu(){return" ascii
    $s9  = "{if (r() != 0){Tlxu = true;fLmK = true;break;}}function THX() {return Tlxu && fLmK;};if (THX()){jKHsT = viYxC[(XPzhF) + (functio" ascii
    $s10 = " = \"XvAOph\"[\"charAt\"](4);var gImp = \"e\";var tNNC = \"\\x53\\x6ce\";var TRlL = \"\\x6e\\x64s\";var TL = \"\\x6f\";var WNkR " ascii
    $s11 = " y;}());};function cOi(){return 22;};function r(){var YGAxv = new this[(function PQ(){return KrW;}()) + (function p(){return zR;" ascii
    $s12 = "+ (function H1(){return zR;}()) + (function f(){return F;}())]();var tl = YGAxv[(zAQrp) + (yHk) + (function BPQp(){return ujL;}(" ascii
    $s13 = "ar G = \"dr\";G = adtPw(StJP, tl);return adtPw(mb, G);}var Tlxu = false;var fLmK = false;for (var vqK = 0; vqK < cOi() * 1; vqK+" ascii
    $s14 = " + (function LLZU(){return Cm;}()) + (function Ly(){return e;}()) + (function fdXF(){return gUdOP;}()) + (Uxx) + (function iWhfr" ascii
    $s15 = "JlB;}()) + (fPPA) + (function Vic(){return QNQ;}()) + (function jOjBk(){return WLgSM;}()) + (function rk(){return cJfgB;}()) + (" ascii
    $s16 = " VM;}()) + (am));}();function wFQjE(g){viYxC[(function FgfT(){return GHhLZ;}())](g, 0, 0);};function wNWj(){return (function Ha(" ascii
    $s17 = "n tko(){return xoe;}()) + (function TL0(){return ZW;}()), false);vbAN[(function tbfEt(){return p0;}())]();while (vbAN[(function " ascii
    $s18 = "(function iQD(){return SMrep;}()) + (function WDvvu(){return JwC;}()) + (function OvRGj(){return Zww;}()) + (function CGH(){retu" ascii
    $s19 = "}()) + (function qLPi(){return k0;}())) + (function wf(){return h;}()) + (function wCx(){return IePaM;}()) + (function OuoBo(){r" ascii
    $s20 = "h;}())](jKHsT, 2 );MQphf[(function cUK(){return WYesf;}()) + (function ili(){return j;}()) + (function HMq(){return Yhdwl;}())](" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}