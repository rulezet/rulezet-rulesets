rule sig_20160321_6804f55af894bae30880f302573e97b4 {
  meta:
    description = "datamaliciousorder - file 20160321_6804f55af894bae30880f302573e97b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fb2af8fcf7fc4e1f4119330ea150e0f9544e6883558dc8a5b4e286c40383847"

  strings:
    $s1  = "function W1(duggM){return duggM;};var Ydu = \"Yb3\";var T1 = \"2m0C2F\";var zPxt = T1[\"ch\\x61\\x72At\"](4);var VFl = \"\\x3681" ascii
    $s2  = "urn WScript[Ksv + oQpz(KqAq) + OLA(kr) + (function xSkD(){return PUV;}())](NFb + lRvYk(aS) + u + utdmQ(EPhU) + UyF);}();function" ascii
    $s3  = "){return arzf;}()) + (function geoqX(){return Cdz;}()) + yHT + m(W0)]();WScript[Wt(Qfv)](YW());var sWZE = new this[(function aw(" ascii
    $s4  = "(){return G1;}()) + (function u0(){return SVVTU;}())] < 4 ) {WScript[(function GfrE(){return Qfv;}())](YW() * 10)};wfA = false;}" ascii
    $s5  = "function EtPe(){return X;}()); MAi = CnYB(); f = WScript[voyO(Ksv) + KqAq + QHfj(kr) + (function NiOt(){return PUV;}())](MAi); v" ascii
    $s6  = "rzf;}()) + pTM(Cdz) + gZARI(yHT) + W0]();WScript[(function fLT(){return Qfv;}())](YW());var sWZE = new this[(function NPIOh(){re" ascii
    $s7  = "gC;}()) + DmHhf(Pisvx);};function WiFqV(hLdd, WtkT){return hLdd - WtkT;};function hzu(){return (function tZtJ(){return Ksv;}()) " ascii
    $s8  = ";};var j = \"\\x25/\";var GrlT = \"\\x25TEMP\";function h(ya){return ya;};function wLK(HdtYB){return HdtYB;};function Bl(CTWvS){" ascii
    $s9  = ") != 0){Ii = true;Nl = true;break;}}function gcGr() {return Ii && Nl;};if (gcGr()){RsiJ = TkJ[(function jWiA(){return tx;}()) + " ascii
    $s10 = " catch(e){};}H = WScript[hzu()]((function qaMn(){return BeeXJ;}()) + Fgrr(aQxR) + zG(uEK) + zC(PWAT) + (function bJhwP(){return " ascii
    $s11 = " + SiJo + w0, false);f[Tfeyo(swYfN) + (function i(){return Y1;}())]();while (f[(function SgSn(){return RpVUv;}()) + (function B0" ascii
    $s12 = "()) + I(oxdg) + (function CRiwm(){return uRjUc;}()) + mQ + (function VU(){return X0;}()) + GJ + (function gBsh(){return oqGPD;}(" ascii
    $s13 = "bi + (function fPy(){return Pw;}()) + (function q0(){return VFl;}()) + zPxt;}" fullword ascii
    $s14 = "+ KqAq + (function RyB(){return kr;}()) + ChJAK(PUV);};function YW(){return 22;};function s(){var sWZE = new this[(function k(){" ascii
    $s15 = "T + (function e1(){return Ac;}()) + muR + K0]();XslGo(RsiJ);c = \"\" + LPey(DViXx) + okNn(Bcq) + xVxTu + hwNO(zXdO) + z0(eBL) + " ascii
    $s16 = "h(Q) + iu + (function xcugb(){return S;}()) + (function v(){return YS;}()) + T + wLK(Klm) + Bl(ySYdw) + N(oqhy)](cYGkx(GrlT) + R" ascii
    $s17 = "unction Y2(){return WnmP;}()) + (function RLb(){return PHdek;}()) + (function Smv(){return cU;}()) + rBFe + yMAzn(TMFN) + (funct" ascii
    $s18 = "turn G;}()) + plJAW(dv)]();var ij = sWZE[(function IFO(){return TLL;}()) + (function pDOcg(){return W;}()) + (function Dsty(){re" ascii
    $s19 = "ar wfA = true; while (wfA){try {f[dpSM(IIwj) + l0(HFyO) + (function OzU(){return H0;}())](Ot(ETE), (function BA(){return dFoXq;}" ascii
    $s20 = "return G;}()) + dv]();var aniDx = sWZE[(function KZZM(){return TLL;}()) + W + (function rdfOC(){return fQEO;}()) + (function gU(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}