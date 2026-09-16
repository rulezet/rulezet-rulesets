rule sig_20160321_6f8717add52592fc9cdb93172302e08f {
  meta:
    description = "datamaliciousorder - file 20160321_6f8717add52592fc9cdb93172302e08f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88b7cf8ba52345c6923986d651597311683cb1ff744e91467fdc888173971395"

  strings:
    $s1  = "unction o1(){return pF;}()) + (function xmsuJ(){return mIJ;}()) + UTzHE(WjH) + x]();WScript[KW(R) + LqYL(YxBHR)](UBjmy());var FV" ascii
    $s2  = "}()) + (function oPNp(){return TiIFo;}()) + (function NG(){return Wcwii;}()) + Inh(lhIJ) + DE(PBdiv); UZm = J(); rGvV = WScript[" ascii
    $s3  = ");var uxkM = \"\\x43\\x72\";var CZ = function M() {return WScript[IPCCc(uxkM) + IZc(Vj) + (function U(){return LMuH;}()) + QWE(t" ascii
    $s4  = "var AWwX = \"62\";var RFoNM = \"\\x3681\";var ja = \"\\x321\\x383\";function EXrp(tjV){return tjV;};var OpAR = \"as\\x64\\x66\";" ascii
    $s5  = "0 + V(sJQJn);};function o(eWOXb, vhGh){return eWOXb - vhGh;};function LASZN(){return (function JvhHa(){return uxkM;}()) + uGomS(" ascii
    $s6  = " (var ikBUH = 0; ikBUH < UBjmy() * 1; ikBUH++){if (JTkvv() != 0){WZT = true;dH = true;break;}}function YuGX() {return WZT && dH;" ascii
    $s7  = "eturn LIpq;}())] < 4 ) {WScript[(function h(){return R;}()) + eL(YxBHR)](UBjmy() * 10)};D = false;} catch(e){};}GmML = WScript[L" ascii
    $s8  = "{return OuhEz;}()) + mKC(dSR), false);rGvV[LcRbe(KUHGi)]();while (rGvV[O(iq) + (function QqG(){return YlA;}()) + (function T(){r" ascii
    $s9  = "0(){return mascf;}()) + (function US(){return JfoX;}())](WGrRc, 0, 0);};function J(){return o0(IP) + TaeeK(jds) + DAnN(YQvx) + j" ascii
    $s10 = "nY = new this[q(hNaUr)]();var gmcb = FVnY[(function dGGja(){return pF;}()) + mIJ + (function ko(){return WjH;}()) + aBU(x)]();WS" ascii
    $s11 = "()) + zWMoc(yIWvL) + (function oLxk(){return fZCbJ;}()) + cOrf(sklk) + (function w1(){return gVApp;}()) + Qzj + (function zYbj()" ascii
    $s12 = "};if (YuGX()){XW = CZ[(function QdYWI(){return Rz;}()) + Cn(Aj) + (function XsD(){return N0;}()) + tAI + z(gixir) + JI + (functi" ascii
    $s13 = " + wiuA + (function LVli(){return wX;}()) + Bx + cRoOs(KPKcN)]);GmML[(function SL(){return pgWHs;}()) + (function P(){return Wz;" ascii
    $s14 = "D){try {rGvV[sJ]((function pPYHB(){return ekpU;}()) + LlMv, fRM + (function saeSy(){return w0;}()) + (function Ckd(){return h1;}" ascii
    $s15 = "g(){return Pqvk;}())) + (function G0(){return xW;}()) + (function iqSO(){return w;}()) + s0(XsLov) + (function D0(){return PDgP;" ascii
    $s16 = "W);kJ = \"\" + qK + (function mQK(){return PM;}()) + BwNB + AKjfN(YxDa) + axk + MZPsc + (function dm(){return Xs;}()) + Vvt + Wx" ascii
    $s17 = "ction SDZYU(){return wpUn;}())] = 1;GmML[VRcw(veim) + (function cdAo(){return Y;}()) + CVoiA](rGvV[(function S0(){return C0;}())" ascii
    $s18 = "Xrp(OpAR) : (function SU(){return ja;}()) + (function QI(){return RFoNM;}()) + AWwX;}" fullword ascii
    $s19 = "cript[l(R) + YxBHR](UBjmy());var FVnY = new this[hNaUr]();var G = FVnY[WMQis(pF) + mIJ + xHWP(WjH) + (function C(){return x;}())" ascii
    $s20 = "on Pa(){return Sm;}()) + (function u(){return Laq;}()) + JvGtM](yolg + (function d(){return Jlnt;}()) + h0(DImx) + (function GzS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}