rule sig_20160321_9ef6ae5200780d6257e69951dc7b7642 {
  meta:
    description = "datamaliciousorder - file 20160321_9ef6ae5200780d6257e69951dc7b7642.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb10077806a369e49e5028ac271e0ea80393b248f7bd68c1a40ff51daddaf80e"

  strings:
    $s1  = "var AzTq = \"6\\x32\";var ae = \"81\";var nJpl = \"21\\x383\\x36\";function PCb(wlU){return wlU;};var iTxWv = \"\\x64\\x66\";var" ascii
    $s2  = "R) + KYd(qtuej) + bDMXA(Fli) + (function muQ(){return ip;}()) + xwCyn(p2); vqTc = PpSs(); VUK = WScript[mOtik + QWrP(nR) + GQ](v" ascii
    $s3  = "+ XM(kQle)]();while (VUK[J0(z1) + a0 + NQIT + (function mKfZR(){return UG;}()) + (function FL(){return nF;}())] < 4 ) {WScript[(" ascii
    $s4  = "function NFn() {return WScript[mYKt(mOtik) + elVy(nR) + SQKPu(GQ)](Swic + (function TNlX(){return o;}()) + (function Jf(){return" ascii
    $s5  = "eturn U;}()) + (function VjIr(){return B;}()) + HU(OXT) + (function gkc(){return Wa;}()) + SDzqI(iRmR) + r(hsiD)]();WScript[(fun" ascii
    $s6  = "T;}()) + Wa + (function DF(){return iRmR;}()) + EoNv(hsiD)]();WScript[(function ye(){return NmBb;}()) + fZs(eFL)](lW());var AMk " ascii
    $s7  = " < lW() * 1; Kkav++){if (LzI() != 0){S = true;YsdzQ = true;break;}}function zY() {return S && YsdzQ;};if (zY()){BzBN = y[(functi" ascii
    $s8  = "function w(){return NmBb;}()) + W0(eFL)](lW() * 10)};Tb = false;} catch(e){};}OoSa = WScript[k()]((function IaO(){return dTsq;}(" ascii
    $s9  = "OXT = NMs[\"ch\\x61rA\\x74\"](3);var B = \"\\x6c\";var U = \"\\x69\";var OtCQr = \"\\x4d\";var JcJnd = \"get\";function NjC(naKn" ascii
    $s10 = ";var PXOW = AMk[iiGjZ(JcJnd) + (function mv(){return OtCQr;}()) + n(U) + (function p(){return B;}()) + (function beO(){return OX" ascii
    $s11 = "eturn hQP;}()) + h1(bY) + (function k2(){return sqes;}()) + (function kIIAf(){return jvq;}()) + (function la0(){return Gkq;}()) " ascii
    $s12 = ")))]();OoSa[NEPM + (function sE(){return ocf;}())] = 1;OoSa[(function JXPKl(){return igd;}())](VUK[YJWV(oXz) + bj(EDE) + RV(f0) " ascii
    $s13 = "+ ScN(odn) + (function gPcSx(){return pVg;}())]);OoSa[(function nbdwH(){return xu;}()) + ipy(ej)] = 0;OoSa[Eg(HFF) + ogtwO(Za) +" ascii
    $s14 = "n g;}()), Rj(C) + QVHfs + (function Cg(){return lNVXi;}()) + (function QW(){return ZXc;}()) + (function xWRET(){return oPgY;}())" ascii
    $s15 = "(){return dD;}()) + Bg(DMj) + C0(YrW) + (function jVq(){return fhNSI;}()) + (function D1(){return Wblx;}()) + (function sTkP(){r" ascii
    $s16 = " De(D0) + jHyb(hkXtS)](BzBN, 2 );OoSa[BsRbz + (function zZ(){return i;}())]();kchH(BzBN);zgWQm = \"\" + J1(kHsl) + (function Ynd" ascii
    $s17 = ")) + (function eB(){return mrYSK;}()) + F0(Ua) + D(vMcP));OoSa[((function ei(){return OJX;}()) + (function WlIic(){return Pwr;}(" ascii
    $s18 = "rn mOtik;}()) + z(nR) + (function z0(){return GQ;}());};function lW(){return 22;};function LzI(){var AMk = new this[NjC(eJjy)]()" ascii
    $s19 = "CQr + U + ptZd(B) + (function m(){return OXT;}()) + uMH(Wa) + (function la(){return iRmR;}()) + Zd(hsiD)]();var zgWQm = \"k0\";z" ascii
    $s20 = "qTc); var Tb = true; while (Tb){try {VUK[(function f(){return OJX;}()) + (function JUKWk(){return Pwr;}())]((function h0(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}