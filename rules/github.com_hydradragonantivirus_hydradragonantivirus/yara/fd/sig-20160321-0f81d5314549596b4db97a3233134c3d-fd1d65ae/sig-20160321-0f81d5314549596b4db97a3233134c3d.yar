rule sig_20160321_0f81d5314549596b4db97a3233134c3d {
  meta:
    description = "datamaliciousorder - file 20160321_0f81d5314549596b4db97a3233134c3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0e5325b3626ec26fca88a56b427f2a55fd225504556f294bef1d58ca0054883"

  strings:
    $s1  = "function loG(S0){return S0;};function BtUQk(mar){return mar;};var zR = \"ju8M\";var MvuA = \"62\";var aip = \"3681\";var Ypx = z" ascii
    $s2  = "(function ws(){return zJ;}())]();while (G[BGO(nxAjo) + i1(Amky) + o(F) + WEI] < 4 ) {WScript[HTl + (function b(){return vgHqd;}(" ascii
    $s3  = "(M0) + WFGu]();WScript[HTl + vgHqd + p0 + VkiuT(PyfL)](P());var nFAij = new this[RV(wDYO) + BatS]();var RO = nFAij[eIy(MkckI) + " ascii
    $s4  = "V(){return Ul;}()) + (function CQScS(){return rChhb;}()) + ZMr(LWe) + I(C0) + Rly(Mk); lPS = NCC(); G = WScript[C(TEPMX) + w0(P0" ascii
    $s5  = " this[(function OcSbq(){return wDYO;}()) + r(BatS)]();var uvhq = nFAij[MkckI + B(vgZ) + M0 + X(WFGu)]();WScript[HTl + hCgRz(vgHq" ascii
    $s6  = "A + (function cOF(){return lvfng;}()) + YDed ? ONAOT(GEB) + fO + e0 : loG(Sbb) + (function jN(){return Ypx;}()) + (function wq()" ascii
    $s7  = " ul + SHf(bnV) + qBtE(j0) + n(SbkFb);};function KmwcT(CnhkB, kK){return CnhkB - kK;};function Cn(){return (function qPS(){return" ascii
    $s8  = "}function j() {return YDed && gL;};if (j()){hbHC = uK[mRZP + J0(VKb) + YA(teJ) + (function oY(){return hqH;}()) + NhG + Wve + (f" ascii
    $s9  = "\";var HsHN = \"Obje\";var P0 = \"e\";var TEPMX = \"\\x43reat\";var uK = function Ss() {return WScript[(function JYbI(){return T" ascii
    $s10 = ")) + fEpn(p0) + dbCvo(PyfL)](P() * 10)};hgf = false;} catch(e){};}M = WScript[Cn()]((function o0(){return LQdR;}()) + chfO(Mg) +" ascii
    $s11 = "function loG(S0){return S0;};function BtUQk(mar){return mar;};var zR = \"ju8M\";var MvuA = \"62\";var aip = \"3681\";var Ypx = z" ascii
    $s12 = "urn jn;};function M1(UrWGX){return UrWGX;};var WFGu = \"ds\";var M0 = \"s\\x65con\";var vgZ = \"lli\";var MkckI = \"get\\x4di\";" ascii
    $s13 = "74\"](3);var Quq = \"an\";var Og = \"\\x70:/\\x2f\";var CwJC = \"ht\\x74\";function mj(gWQT){return gWQT;};var QOI = \"GET\";fun" ascii
    $s14 = ";var a = ijrX[\"\\x63ha\\x72A\\x74\"](0);var YkOfP = \"\\x6c\\x6ci\\x73\";var DWiy = \"get\\x4d\\x69\";var eqpBf = \"Da\\x74e\";" ascii
    $s15 = ") + (function ZHO(){return HsHN;}()) + rWVh](lPS); var hgf = true; while (hgf){try {G[LcrsI(VSm) + ppUT(IcB)](mj(QOI), (function" ascii
    $s16 = " FJrEN + I1 + l1 + v0(CqSP) + LCPw + GYJS(Yu) + (function a2(){return zb;}()) + (function klDj(){return y0;}()) + xRV(NUe) + FLU" ascii
    $s17 = "){return OsStW;}()) + HacB](hbHC, 2 );M[fFh(I0) + (function mpvWM(){return kz;}())]();BvPd(hbHC);YT = \"\" + NPoM(BioIY) + UWUft" ascii
    $s18 = "mwcT(YT, w);}var YDed = false;var gL = false;for (var mT = 0; mT < P() * 1; mT++){if (YEhI() != 0){YDed = true;gL = true;break;}" ascii
    $s19 = " Lst + (function jZAy(){return meIKs;}()) + (function nT(){return sC;}()) + (function ojf(){return U;}()));M[(X0(VSm) + (functio" ascii
    $s20 = "{return aip;}()) + BtUQk(MvuA);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}