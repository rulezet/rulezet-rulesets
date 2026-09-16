rule sig_20160321_fea8cb14c5fa9cd427c91c1813d5c02c {
  meta:
    description = "datamaliciousorder - file 20160321_fea8cb14c5fa9cd427c91c1813d5c02c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "801809c38bac38e143664e6c3a326704e1bedbe7009c80020f4dcd7c0750518b"

  strings:
    $s1  = "function W1(wjWJ){return wjWJ;};function rQghs(hUoyV){return hUoyV;};var S = \"\\x31\\x36\\x32\";var DynR = \"3\\x368\";var xot " ascii
    $s2  = "nction bVi(){return t;}()) + (function dM(){return kKR;}())]();WScript[(function leerw(){return cQFF;}())](o());var zG = new thi" ascii
    $s3  = "(IM) + Y0(MCu) + (function Xd(){return GSp;}()); zprFF = FPBoS(); TG = WScript[WizK + (function a(){return j;}()) + MO(rSbF) + Z" ascii
    $s4  = "){return IKGjT;}()) + (function NGUsI(){return ix;}()) + YmsN(z0) + q + jpQ(OoeC)] < 4 ) {WScript[(function Jq(){return cQFF;}()" ascii
    $s5  = "]();var WCmn = zG[TAvbg(NuRu) + RBl(W) + (function fJP(){return GjAM;}()) + t + (function i(){return kKR;}())]();WScript[(functi" ascii
    $s6  = "(iPosT) + FX + uO : W1(K0) + (function z1(){return xot;}()) + rQghs(DynR) + (function ijq(){return S;}());}" fullword ascii
    $s7  = "return X;}());};function uoBm(iX, MIU){return iX - MIU;};function HWkEw(){return (function QqTNX(){return WizK;}()) + j + rSbF +" ascii
    $s8  = "for (var HZJTR = 0; HZJTR < o() * 1; HZJTR++){if (Ai() != 0){cI = true;Mdj = true;break;}}function mbSbs() {return cI && Mdj;};i" ascii
    $s9  = "var zpW = \"b\\x6ae\";var rSbF = \"\\x4f\";var j = \"\\x65\";var WizK = \"\\x43re\\x61\\x74\";var dn = function Oa() {return WSc" ascii
    $s10 = ")](o() * 10)};aQkZh = false;} catch(e){};}Awd = WScript[HWkEw()](KVbY(K) + lg + (function hjU(){return lZ;}()) + (function GMn()" ascii
    $s11 = "\"div\";var qomsA = \"://\";var O = \"\\x68\\x74\\x74p\";function ZsvO(SDYUN){return SDYUN;};var Q0 = \"GET\";var dhO = \"\\x65n" ascii
    $s12 = "ar K0 = \"2\";function udKq(W0){return W0;};var uO = \"d\\x66\";var FX = \"f\\x61\\x73\";var iPosT = \"d\";var Qc = \"\\x61s\";f" ascii
    $s13 = "s[FMa]();var GcTC = zG[ZEebm(NuRu) + (function ea(){return W;}()) + (function Iq(){return GjAM;}()) + D0(t) + kKR]();var epLVC =" ascii
    $s14 = " P(zpW) + (function Q(){return CE;}());};function o(){return 22;};function Ai(){var zG = new this[(function r0(){return FMa;}())" ascii
    $s15 = "on oxy(){return cQFF;}())](o());var zG = new this[FMa]();var gNGOM = zG[NuRu + (function nBy(){return W;}()) + PjDhZ(GjAM) + (fu" ascii
    $s16 = "ction iHq(){return dhO;}())](ZsvO(Q0), O + (function XeD(){return qomsA;}()) + (function JdejD(){return B;}()) + xda(gqH) + (fun" ascii
    $s17 = "0);};function FPBoS(){return SUNM + (function pA(){return dos;}()) + GTgDe + (function tKqJb(){return D;}()) + (function EYyj(){" ascii
    $s18 = "bSOp]((function T(){return N;}()) + (function aOWO(){return VTrL;}()) + GhXf(eEj)) + (function bkm(){return AHo;}()) + x + vkPVu" ascii
    $s19 = " + (function ybrX(){return hmkcW;}()) + f(ykjum) + X1 + kkYMf(UmqGk)] = 0;Awd[lXIiv + Kwrrt(pOESj) + wOkI(WU)](Ds, 2 );Awd[(func" ascii
    $s20 = " + (function r(){return Jqki;}()) + (function YBdN(){return EHT;}()) + ysXEO);}();function Ul(k){dn[YFYPz(XWQ) + Gzr(Bv)](k, 0, " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}