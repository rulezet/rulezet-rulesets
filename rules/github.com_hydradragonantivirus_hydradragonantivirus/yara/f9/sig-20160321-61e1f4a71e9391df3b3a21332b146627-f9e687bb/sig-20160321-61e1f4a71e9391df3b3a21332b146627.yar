rule sig_20160321_61e1f4a71e9391df3b3a21332b146627 {
  meta:
    description = "datamaliciousorder - file 20160321_61e1f4a71e9391df3b3a21332b146627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d741ac8ff89beee5d4cca85e033a4b10cda13be82d38487da8a45cbaed4479cc"

  strings:
    $s1  = "function kI(XPd){return XPd;};var sTQ = \"5QKj6WzDKD\";var siN = \"4vOo2rKdph\";var U0 = siN[\"\\x63harA\\x74\"](4);var boJ = sT" ascii
    $s2  = ") + (function H(){return dKd;}()) + goGGe(LoI) + YbO]();WScript[(function fcF(){return NtyY;}()) + (function i(){return knc;}())" ascii
    $s3  = " R0(g)) + kcLA + XBhjg(TFMAj) + dgEXl(a) + e0(Mu) + Eobz(XL); Kx = Kd(); kdl = WScript[pCHoR(xHSob) + (function aqHF(){return LX" ascii
    $s4  = "urn WScript[(function sz(){return xHSob;}()) + (function FF(){return LXods;}()) + XLk(l) + (function Dsz(){return qY;}())](FtoRQ" ascii
    $s5  = "d) + hLDNI(LoI) + YbO]();WScript[(function Tx(){return NtyY;}()) + (function hnbVT(){return knc;}())](YNpB());var k = new this[(" ascii
    $s6  = " false;for (var aDHH = 0; aDHH < YNpB() * 1; aDHH++){if (aT() != 0){y = true;dL = true;break;}}function t() {return y && dL;};if" ascii
    $s7  = ") {WScript[NtyY + knc](YNpB() * 10)};td = false;} catch(e){};}w = WScript[b()](cAE + (function yiZir(){return q;}()) + (function" ascii
    $s8  = "return mGf;}()) + T(lyUl) + gK + (function GnrVQ(){return g0;}()) + c0 + (function KO(){return IgUPZ;}()) + YL(UWPu) + BfS(Zayk)" ascii
    $s9  = "(function O1(){return AWgSl;}())] = 1;w[HWHzE(Ggjqy) + th(ngY)](kdl[(function tLAR(){return COdcW;}()) + (function raC(){return " ascii
    $s10 = "nction iiYf(){return UVI;}())]();var at = k[(function KAOU(){return TZ;}()) + CVix + (function Zp(){return A;}()) + HsT + ZXX(dK" ascii
    $s11 = "eturn ey;}())](mVN, 2 );w[(function VW(){return D1;}()) + (function dW(){return M1;}())]();XyXs(mVN);v = \"\" + (function PG(){r" ascii
    $s12 = "urn ar;}()) + (function VIy(){return gqIck;}()) + AF(iXow) + (function F(){return tQ;}()) + pU(A0) + If(daDYk) + (function S0(){" ascii
    $s13 = ", false);kdl[yKs(Gi)]();while (kdl[OUlS(e1) + (function yZFP(){return D;}()) + (function gk(){return el;}()) + FvFe(UXrdU)] < 4 " ascii
    $s14 = "I) + zxQTP(YbO)]();var v = \"vzK\";v = ikGV(h, at);var Hn = \"lQUhA\";Hn = ikGV(DPWsw, h);return ikGV(v, Hn);}var y = false;var " ascii
    $s15 = "ods;}()) + l + (function hYB(){return qY;}())](Kx); var td = true; while (td){try {kdl[erv + (function f(){return dDBs;}())](d, " ascii
    $s16 = "n UFC(){return l;}()) + (function kTgH(){return qY;}());};function YNpB(){return 22;};function aT(){var k = new this[O(nT) + (fu" ascii
    $s17 = "(function W(){return YV;}());};function ikGV(Nyr, vmCAI){return Nyr - vmCAI;};function b(){return xHSob + bkyT(LXods) + (functio" ascii
    $s18 = "function zE(){return nT;}()) + (function u(){return UVI;}())]();var h = k[MTEu(TZ) + CVix + A + (function jQGrP(){return HsT;}()" ascii
    $s19 = " + (function Qn(){return SszsD;}()) + (function NtUm(){return V;}()) + Lr(Eeztd) + gtFY(FdM) + z(e));}();function XyXs(GT){uBr[G" ascii
    $s20 = "jq + jn(koC) + zie + ROtov(nXO) + (function Xti(){return bUS;}()) + XUIk + (function eKR(){return hHcPI;}()) + (function wkjx(){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}