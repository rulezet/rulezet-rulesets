rule sig_20160321_ba478b88aa73af452ed1c84ab4cac4d6 {
  meta:
    description = "datamaliciousorder - file 20160321_ba478b88aa73af452ed1c84ab4cac4d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3337386294cad880477cb584e27cadc2ec73f05723d0546d6b84a44dc273a30"

  strings:
    $s1  = "function JI(NTYY){return NTYY;};function lwzCU(zrcTs){return zrcTs;};function Ak(AD){return AD;};var DyxD = \"2\";var KWU = \"" ascii
    $s2  = "wGa(){var la = new this[RrbHU]();var QGOjn = la[KUagj + TVl + hh(kMAv) + Kpsad + ZJOy(Oi) + cIorq + Kbm]();WScript[(function VlU" ascii
    $s3  = " RA;};var Lnd = \"\\x74\";var he = \"bjec\";var sMEpJ = \"teO\";var X = \"Cre\\x61\";var Xyry = function O() {return WScript[X +" ascii
    $s4  = "+ kMAv + Kpsad + oa(Oi) + cIorq + jK(Kbm)]();WScript[zdFKz(IqF) + (function Jvb(){return cz;}())](Qgnn());var la = new this[WpcU" ascii
    $s5  = "(function npHI(){return AP;}()) + (function DEeft(){return l0;}()) + rRLqv(DKV) + a0 + Q; NTKmY = SRJi(); LqXn = WScript[(functi" ascii
    $s6  = "}())]();while (LqXn[TK + mQ + (function Au(){return guiKH;}())] < 4 ) {WScript[YbPcS(IqF) + (function S(){return cz;}())](Qgnn()" ascii
    $s7  = "i(){return (function SWUx(){return H;}()) + XSx(J0) + SYiU(rVIL) + HR(X1);};function cXi(AY, f){return AY - f;};function CC(){re" ascii
    $s8  = "k;}}function xfXZ() {return CEk && Ai;};if (xfXZ()){btXhj = Xyry[lEqf(myrTR) + (function AQw(){return vDWLS;}()) + XQI + (functi" ascii
    $s9  = " * 10)};ep = false;} catch(e){};}s = WScript[CC()]((function iP(){return aL;}()) + xjAYV + (function fgz(){return LCh;}()));s[((" ascii
    $s10 = "unction Rs(){return Coe;}()) + (function YCQBw(){return lUWU;}()) + I0 + JzlWv(kKONr) + (function Xs(){return zKy;}()) + (functi" ascii
    $s11 = "on W(){return tFp;}()) + fsQVf + Bz(kq) + ft(fzs) + (function fPxsF(){return DVhfd;}()) + dBuBR(SkZ)](NUhc(B) + BIHTS(zqZnS)) + " ascii
    $s12 = "on Oizf(){return zwoG;}()) + (function wiIJU(){return RB;}()) + (function Qf(){return R;}()) + VjM + T0(HsFC) + CEk ? A0(so) + t" ascii
    $s13 = " mRZHt(){return Oi;}()) + cIorq + qL(Kbm)]();var SF = \"rFf\";SF = cXi(h, QGOjn);var MkTHK = \"EshXy\";MkTHK = cXi(TWkH, h);retu" ascii
    $s14 = ") + (function UjdIN(){return OSD;}()) + vCO(A) + iDI(P) + k1(reJeH), false);LqXn[rdf(Wyw) + FDQ + (function HGpSU(){return Unpe;" ascii
    $s15 = "(){return IqF;}()) + EOy(cz)](Qgnn());var la = new this[(function kfbY(){return RrbHU;}())]();var h = la[tG(KUagj) + cXzpU(TVl) " ascii
    $s16 = ", 2 );s[(function xpbsM(){return et;}())]();wunY(btXhj);SF = \"\" + g0(FvknO) + AYeJq(oFqP) + (function mDnt(){return UP;}()) + " ascii
    $s17 = "(function Rev(){return lHdd;}()), Eeksf(J1) + GmT(skdRv) + bmjn + zXzZ(Nndm) + QBbxP + (function JMBlh(){return Q1;}()) + jVHe(b" ascii
    $s18 = "on OKnb(){return X;}()) + sMEpJ + he + TOoKb(Lnd)](NTKmY); var ep = true; while (ep){try {LqXn[(function HJr(){return NbD;}())](" ascii
    $s19 = "+ E(jYZZK) + RGq + NT(T)]);s[Sb(mbqI) + Mvs(Bgod) + X2 + L + (function f0(){return wScLX;}())] = 0;s[a1 + NTL + CL(BnZzc)](btXhj" ascii
    $s20 = "L(RrbHU)]();var TWkH = la[Bkw(KUagj) + TVl + (function UfaY(){return kMAv;}()) + (function VQiLX(){return Kpsad;}()) + (function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}