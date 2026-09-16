rule sig_20160321_1a37e0839eb549b83bd7a30aa29d64eb {
  meta:
    description = "datamaliciousorder - file 20160321_1a37e0839eb549b83bd7a30aa29d64eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25eeb72d5b9bfd12cb20150f5a42b318cbf6248c2fa646c092c5d18337d19594"

  strings:
    $s1  = "var lp = \"81\\x362\";var cWl = \"\\x321\\x3836\";function w(bnNu){return bnNu;};var mfBq = \"df\";var Ox0 = \"\\x61\\x73\";var " ascii
    $s2  = "}()) + KopBZ]();WScript[c + VmywI](Ac());var jfgbW = new this[p0(KHhh) + (function ibgzs(){return S;}())]();var pb = jfgbW[(func" ascii
    $s3  = " WScript[y()](B(oAS) + JwTaC(ety) + (function XNnFz(){return X2;}()) + WkKh);Zirg[(uEBnm(fPg) + L0(RRdMO))]();Zirg[h] = 1;Zirg[C" ascii
    $s4  = "(DS) + H1(Cz) + WD(CO) + Yus + (function lcWss(){return EhMj;}()); ySoad = jhQ(); qo = WScript[Aj + (function I(){return X;}()) " ascii
    $s5  = "tion gb(){return AZMD;}()) + iZrV(avU) + (function iRUjL(){return fv;}()) + S0(zM) + cvZDz + KopBZ]();WScript[zVim(c) + oiun(Vmy" ascii
    $s6  = "function T() {return WScript[BU(Aj) + eL(X) + nSgt(UJo) + (function dfxaz(){return p;}())](OBzo(L) + ZHxS + JUmgy(InT) + YFH(WNu" ascii
    $s7  = "turn vnR - WS;};function y(){return tS(Aj) + FyX(X) + VKDy(UJo) + (function SA(){return p;}());};function Ac(){return 22;};funct" ascii
    $s8  = "bTL && JK;};if (g()){o = gy[ns(lKN) + sRj(Pwm) + UMZr(TZHiD) + Df + RWWH + (function bBkxA(){return hgW;}()) + Wq]((function fOP" ascii
    $s9  = "tion lJuZQ(){return gZz;}())] < 4 ) {WScript[(function gjM(){return c;}()) + VmywI](Ac() * 10)};fPu = false;} catch(e){};}Zirg =" ascii
    $s10 = "turn q1;}()) + Mgtcu + (function TOdk(){return idCbA;}()) + fApa + YhE(gutc) + GYw + (function YGWVV(){return n;}()) + Rf(A0) + " ascii
    $s11 = "(){return ZlUMG;}()) + (function ZsD(){return WC;}()) + (function a0(){return Jk;}())) + (function Z(){return tPqvU;}()) + SyLWE" ascii
    $s12 = "y) + KNK);}();function sU(ds){gy[(function oAkP(){return Qf;}())](ds, 0, 0);};function jhQ(){return (function A(){return rAwl;}(" ascii
    $s13 = "wI)](Ac());var jfgbW = new this[KHhh + O(S)]();var q = jfgbW[AZMD + IXD(avU) + PblC(fv) + (function HVKkB(){return zM;}()) + H0(" ascii
    $s14 = "ion IVgzp(){var jfgbW = new this[Arwu(KHhh) + S]();var ie = jfgbW[RE(AZMD) + avU + fv + jM(zM) + (function WpYdg(){return cvZDz;" ascii
    $s15 = ")) + (function LC(){return H;}()) + (function GLZLN(){return rw;}()) + QZgt(RX) + Ei + Sy(BpiiY) + er;};function kzn(vnR, WS){re" ascii
    $s16 = "+ R(UJo) + (function zKSB(){return p;}())](ySoad); var fPu = true; while (fPu){try {qo[YLt(fPg) + kc(RRdMO)](v0, (function BHj()" ascii
    $s17 = " = false;for (var ZlyYY = 0; ZlyYY < Ac() * 1; ZlyYY++){if (IVgzp() != 0){cqbTL = true;JK = true;break;}}function g() {return cq" ascii
    $s18 = "(function n0(){return zbxeS;}()) + qSSHG + Qp(udj) + (function xzV(){return lLj;}()) + MJPC(dnJ) + A1 + cqbTL ? (function hkxUh(" ascii
    $s19 = "){return HMoD;}()) + w(Ox0) + (function dU(){return mfBq;}()) : cWl + lp;}" fullword ascii
    $s20 = "cvZDz) + KopBZ]();var yYL = \"CsIk\";yYL = kzn(pb, ie);var ay = \"aP\";ay = kzn(q, pb);return kzn(yYL, ay);}var cqbTL = false;va" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}