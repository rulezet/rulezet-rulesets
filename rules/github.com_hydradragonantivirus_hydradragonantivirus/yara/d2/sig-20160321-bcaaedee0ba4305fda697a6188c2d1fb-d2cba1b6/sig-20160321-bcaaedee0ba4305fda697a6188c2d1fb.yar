rule sig_20160321_bcaaedee0ba4305fda697a6188c2d1fb {
  meta:
    description = "datamaliciousorder - file 20160321_bcaaedee0ba4305fda697a6188c2d1fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33120634c626af2e99259528262966e53381322e67c15792d02456441105163"

  strings:
    $s1  = "var Xje = \"sB1y4v\";var DCZZG = \"62\";var G = Xje[\"\\x63har\\x41t\"](2);var XOr = \"\\x368\";var kDU = \"\\x32\\x3183\";var U" ascii
    $s2  = " AsG + (function jd(){return Il;}()) + (function vLidh(){return I;}()) + LaREs(Sob) + FZ(Fi); fR = WaoWQ(); Cg = WScript[RyAEZ(h" ascii
    $s3  = "zWbe) + oDmD(CFso) + Q(B)]();WScript[(function oMkTq(){return EI;}()) + VQc + MkkPn](F());var kXmWg = new this[GdvGq]();var f = " ascii
    $s4  = "ction Qk(){return QzWbe;}()) + (function ZccsF(){return CFso;}()) + xPHKq(B)]();WScript[EI + VQc + (function MT(){return MkkPn;}" ascii
    $s5  = "= function HAiA() {return WScript[r(hlGOm) + ap + (function r0(){return LemhL;}()) + (function ieSK(){return eMz;}()) + (functio" ascii
    $s6  = "rbx(xtxNM, M){return xtxNM - M;};function Zrn(){return hlGOm + (function y(){return ap;}()) + N(LemhL) + (function QxDOK(){retur" ascii
    $s7  = "e (Cg[jfmK + Xg + zopP(x) + Co] < 4 ) {WScript[LOD(EI) + VQc + MkkPn](F() * 10)};XNQJh = false;} catch(e){};}mrG = WScript[Zrn()" ascii
    $s8  = "FTy = true;BTwk = true;break;}}function K() {return FTy && BTwk;};if (K()){XFtlE = d[(function BJct(){return hhB;}()) + RU(SNMWQ" ascii
    $s9  = ";var ZV = \"\\x6f\\x6eds\";var sX = \"li\\x73\\x65c\";var sQNy = \"\\x4d\\x69\\x6c\";var wi = \"get\";var BnGI = \"Da\\x74e\";fu" ascii
    $s10 = "())](F());var kXmWg = new this[(function O(){return GdvGq;}())]();var Yfm = kXmWg[(function mWIl(){return qs;}()) + M0 + FIikU(Q" ascii
    $s11 = " chTz(PGVly){d[(function m(){return NCZ;}()) + cqE](PGVly, 0, 0);};function WaoWQ(){return (function X(){return IMthn;}()) + (fu" ascii
    $s12 = "()) + (function tAl(){return IxWv;}())](cG(TpaG) + (function TGKuh(){return ZM;}()) + (function bic(){return mff;}())) + YTcPV +" ascii
    $s13 = ", Yfm);return Whrbx(ECgN, TnuUw);}var FTy = false;var BTwk = false;for (var fQKs = 0; fQKs < F() * 1; fQKs++){if (AOwxG() != 0){" ascii
    $s14 = ") + Pwoo(XhC) + zcE(ypAak) + (function Y(){return rm;}()) + (function gPnMx(){return BXrvl;}()) + (function lyaKB(){return eIh;}" ascii
    $s15 = " = 1;mrG[Z + (function psKR(){return UwL;}())](Cg[nznRo(cwzno) + (function Q0(){return d0;}()) + QXoia + PRTA(TSx) + U(MT0) + jF" ascii
    $s16 = " MxgdD + XUipq(xO) + (function fJjBx(){return dD;}()) + qdyy(yVXr) + F0 + (function KB(){return sQ;}()) + E + (function FClb(){r" ascii
    $s17 = ")) + (function GYz(){return XOr;}()) + G + DCZZG;}" fullword ascii
    $s18 = "](Ol + coFU(kBTeC) + (function TJVyc(){return irr;}()) + Uuiu(GH));mrG[(IzE + Ua(WDASu))]();mrG[(function t(){return HmJTb;}())]" ascii
    $s19 = "n L(){return TokuJ;}())](MW(BAuU) + Da + (function GVtH(){return bT;}()) + (function GO(){return r1;}()) + zP(PPx));}();function" ascii
    $s20 = " IzE;}()) + (function KdN(){return WDASu;}())](bD(pdyYt) + r4, (function YMCI(){return X0;}()) + FxaC + IjD + c(ujLl) + TmNI(N0)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}