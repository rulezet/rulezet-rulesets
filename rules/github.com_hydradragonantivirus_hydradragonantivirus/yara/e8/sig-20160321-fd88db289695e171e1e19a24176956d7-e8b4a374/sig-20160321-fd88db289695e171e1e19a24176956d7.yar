rule sig_20160321_fd88db289695e171e1e19a24176956d7 {
  meta:
    description = "datamaliciousorder - file 20160321_fd88db289695e171e1e19a24176956d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68bf7b93e24936ffd20656fe3742b235832dd5f9984c2f750d8945b503ce1082"

  strings:
    $s1  = "function oW(AEIDw){return AEIDw;};function clA(cpMKx){return cpMKx;};var fVU = \"ztaD8ygcZa\";var X = \"1\\x36\\x32\";var m0 = " ascii
    $s2  = "LB(nkFrg)]();WScript[(function IYS(){return wuN;}()) + (function y(){return mBID;}())](NIoB());var kLSm = new this[(function ORZ" ascii
    $s3  = "F(n0) + (function EuDr(){return wqPr;}()) + SVtAw(nkFrg)]();WScript[(function q(){return wuN;}()) + mBID](NIoB());var kLSm = new" ascii
    $s4  = " = r[\"ch\\x61r\\x41t\"](5);var R = \"Cr\\x65\";var xu = function Gi() {return WScript[R + (function qUuzp(){return Peb;}()) + a" ascii
    $s5  = "d = \"%/\";var Hft = \"%TEMP\";function hKfr(Rs){return Rs;};function utA(JoOG){return JoOG;};var Z = \"MnPRL\";var dS = \"gs\";" ascii
    $s6  = ";}}function ZXxhJ() {return h && gMid;};if (ZXxhJ()){yhJcu = xu[hKfr(WC) + (function XcQd(){return xGkd;}()) + XmI + OE + (funct" ascii
    $s7  = "ript[eAN(wuN) + mBID](NIoB() * 10)};OP = false;} catch(e){};}cdv = WScript[ZJ()](HxlyY + UfHD(V0) + (function o(){return cTKzr;}" ascii
    $s8  = "ion ZJ(){return (function IBZ(){return R;}()) + Peb + (function px(){return nkFlM;}()) + (function OWHR(){return LN;}()) + ja(uG" ascii
    $s9  = "()) + Y1);cdv[(Y0(vwR))]();cdv[nQ] = 1;cdv[v0(WI)](uL[(function MUxC(){return WaMzK;}()) + (function gCXM(){return F;}()) + (fun" ascii
    $s10 = "urn WDwju;}()) + (function s1(){return d0;}()) + MVG(IaSwA) + At(Wz) + aniT(eo) + EzVE(kXQeh) + vvA(O3) + (function HYKIA(){retu" ascii
    $s11 = "HUy) + T;};function NIoB(){return 22;};function XXZB(){var kLSm = new this[vj]();var jxo = kLSm[(function BmXV(){return sHrS;}()" ascii
    $s12 = "urn DX;}()) + xqnvR(Og) + RXmvS : udB + oW(MhdxB) + (function h1(){return m0;}()) + clA(X);}" fullword ascii
    $s13 = " + LN + uGHUy + fXMUn(T)](u(EeN) + HUTEb + T0(Xdnk) + (function zcyS(){return Ttvn;}()));}();function qx(stHmI){xu[O0 + (functio" ascii
    $s14 = ") + (function eBQe(){return lw;}()) + (function L(){return s;}()) + EiHtf(zSNk) + PQm(n0) + (function iXOB(){return wqPr;}()) + " ascii
    $s15 = "K0) + (function YbERn(){return aV;}())](yhJcu, 2 );cdv[NNmxM]();qx(yhJcu);XbsDv = \"\" + LfqyR + CsWtY(BOuX) + (function xou(){r" ascii
    $s16 = "sG);}var h = false;var gMid = false;for (var icWPP = 0; icWPP < NIoB() * 1; icWPP++){if (XXZB() != 0){h = true;gMid = true;break" ascii
    $s17 = " this[(function BsG(){return vj;}())]();var KDynn = kLSm[cCqA(sHrS) + (function Et(){return lw;}()) + s + zSNk + n0 + wqPr + (fu" ascii
    $s18 = "(OEJat) + (function m(){return AOz;}()) + Df + lTF(Pn), false);uL[J]();while (uL[wAwtu + Z0(UyG) + dvqb + BCSHK(yCI)] < 4 ) {WSc" ascii
    $s19 = "rn rR;}()) + hnj + (function Ipu(){return eJOOz;}()) + ETyG(RsG) + h ? (function Jkl(){return vzjVS;}()) + (function llwYd(){ret" ascii
    $s20 = "n EMmqw(){return Y;}()) + (function C0(){return C;}())](stHmI, 0, 0);};function hRf(){return (function u0(){return sHMZu;}()) + " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}