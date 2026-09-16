rule sig_20160318_636a520b0d2b4bf42d2ade4f370f7987 {
  meta:
    description = "datamaliciousorder - file 20160318_636a520b0d2b4bf42d2ade4f370f7987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaebf7570bcdc407db7d7757e7eafaadae5a3833eb03fce028e7116e07ce9a34"

  strings:
    $x1  = "var Ll = \"\\x21\";var skpZ = \"a\\x69\\x6e\";var OU = \"y ag\";var hcpG = \"4wrB\"[\"charAt\"](2);var ML = \"e, t\";var VL = \"" ascii
    $s2  = "function V(){return ifG;}()) + (deYx);}else{WScript.Echo((function YhxZ(){return VL;}()) + (function KTB(){return ML;}()) + (hcp" ascii
    $s3  = "4 ) {WScript[(function M0(){return ib;}()) + (function m(){return Hgn;}())](I() * 10)};Rj = WScript[Aqc()]((function O(){return " ascii
    $s4  = "= i(); uQQ = WScript[(function qvMR(){return LkrKc;}()) + (function WA(){return FaXQJ;}()) + (function v(){return dWQnv;}()) + (" ascii
    $s5  = "nction lMQXD(){return eLBpn;}())]();WScript[(function UEseg(){return ib;}()) + (function qrC(){return Hgn;}())](I());var uM = ne" ascii
    $s6  = "]();WScript[(function OH(){return ib;}()) + (function wJeih(){return Hgn;}())](I());var uM = new this[(function DXIp(){return W;" ascii
    $s7  = "function G(){return PfA;}())](zEDNy);uQQ[(function ROWe(){return YW;}()) + (waf)]((function bDLlS(){return d0;}()), (function Gp" ascii
    $s8  = "};function h(e, Ypv){return e - Ypv;};function Aqc(){return (function ad(){return LkrKc;}()) + (function aLZ(){return FaXQJ;}())" ascii
    $s9  = "= true;break;}}function M() {return TKJwz && SReSH;};if (M()){lkw = gZ[(function Kq(){return Hv;}()) + (function d(){return cgxu" ascii
    $s10 = "x57S\";var PfA = \"e\\x63t\";var dWQnv = \"bj\";var FaXQJ = \"eateO\";var LkrKc = \"\\x43\\x72\";var gZ = function cf() {return " ascii
    $s11 = "G) + (function im(){return OU;}()) + (skpZ) + (function YuA(){return Ll;}()));}" fullword ascii
    $s12 = "n Yvk(qZc){gZ[(function MjDWN(){return Xthy;}())](qZc, 0, 0);};function i(){return (fEvn) + (function CB(){return IFvi;}()) + (f" ascii
    $s13 = "()) + (function Brfh(){return Yv;}()) + (function N(){return tvW;}()) + (function vu(){return uzTvp;}()) + (function Bc(){return" ascii
    $s14 = "tion C(){return vpB;}()) : (function jk(){return TtuT;}()) + (function Jv(){return A0;}()) + (function iCp(){return bPa;}()) + (" ascii
    $s15 = "ion YgepH(){return rJkL;}()) + (function yMCU(){return LJZ;}()) + (function z(){return Qfo;}()) + (function jaRV(){return vF;}()" ascii
    $s16 = "tion jc(){return XL;}()) + (function UY(){return TTlyQ;}()) + (function Z(){return pizTA;}()) + (function dk(){return eLBpn;}())" ascii
    $s17 = "HQzV;}()) + (function Qk(){return cfhL;}()) + (SQ) + (function LWoe(){return At;}()) + (function iMe(){return Lfq;}()));Rj[((fun" ascii
    $s18 = "eturn WdKGl;}()) + (function lO(){return vVd;}()) + (BXnRD)]((function qUnEw(){return kRgk;}()) + (function IjTuE(){return uwcc;" ascii
    $s19 = "}())) + (function FN(){return ELYh;}()) + (IXDU) + (function ab(){return SeW;}()) + (y) + (function hiR(){return aP;}()); zEDNy " ascii
    $s20 = "ion Xk(){return fB;}()) + (rA) + (function rg(){return ZG;}()) + (function mm(){return JvM;}())] = 0;Rj[(function n(){return vS;" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}