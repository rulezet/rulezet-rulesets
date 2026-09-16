rule sig_20160321_5ce0489a0962a5e9f0945c387403f01f {
  meta:
    description = "datamaliciousorder - file 20160321_5ce0489a0962a5e9f0945c387403f01f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be8f42a43f4b3663e583e085468244a841f53173ec0b2a35fe9f0c476248d38a"

  strings:
    $x1  = "function iwzU(Wpns){return Wpns;};function KwpJ(UJzR){return UJzR;};var X1 = \"8O\";var WqV = \"2\";var bB = \"36816\";var lgNv " ascii
    $s2  = ";WScript[QIdO + PEzB + (function Qup(){return Dyxs;}())](nd());var LDrS = new this[(function u(){return GTgWB;}()) + hWdep]();va" ascii
    $s3  = "(function N0(){return OWIOr;}())]();while (a[VV(N1) + (function wc(){return yBR;}()) + MACz(Xf)] < 4 ) {WScript[Zb(QIdO) + (func" ascii
    $s4  = " function GzKJ() {return WScript[iYClu(G) + mHTo(aL) + dQYF(klZqe) + KXL(Hr)](uCrC + c(Aas) + j(JM) + WGS(pKoJ) + PzLfH(cv) + cQ" ascii
    $s5  = "VmWE = LDrS[NW(Tavu) + WQ + r(mASTp) + (function hrgE(){return eDq;}()) + (function E0(){return hTE;}()) + cFE]();WScript[(funct" ascii
    $s6  = "unction T0(){return Jo;}()) + (function r0(){return Je;}()) + (function V1(){return bF;}()); QiCt = Kc(); a = WScript[T(G) + EcJ" ascii
    $s7  = "ion Hhb(){return QIdO;}()) + PEzB + (function Irat(){return Dyxs;}())](nd());var LDrS = new this[(function X(){return GTgWB;}())" ascii
    $s8  = "(function XYwAl(){return CK;}());};function H(k, g){return k - g;};function uUT(){return (function Cj(){return G;}()) + (functio" ascii
    $s9  = "eturn Jz && KuBjM;};if (sKiW()){CPhW = W[(function Aqr(){return o0;}()) + JQ + (function bnVT(){return Jcyk;}()) + (function gTl" ascii
    $s10 = "tion vCm(){return PEzB;}()) + (function vPd(){return Dyxs;}())](nd() * 10)};b = false;} catch(e){};}VZcZ = WScript[uUT()]((funct" ascii
    $s11 = "n NP(){return aL;}()) + klZqe + Hr;};function nd(){return 22;};function LD(){var LDrS = new this[y(GTgWB) + xFZv(hWdep)]();var h" ascii
    $s12 = "Mp(WSx) + pZSH + FjyO + xYRNY + (function K(){return QJuE;}()) + (function tyry(){return cvJa;}()) + TMQ(v) + (function yHm(){re" ascii
    $s13 = " + (function DHOF(){return hWdep;}())]();var wGsd = LDrS[Tavu + (function evrh(){return WQ;}()) + lK(mASTp) + eDq + hTE + cFE]()" ascii
    $s14 = "(aL) + klZqe + zFjBS(Hr)](QiCt); var b = true; while (b){try {a[ZQVyO]((function WSc(){return Ya;}()), uBRx + (function gDTz(){r" ascii
    $s15 = "(){return ZaXMa;}()) + Px(YHa) + (function mibz(){return PxFH;}()) + Hgm + eq(w) + (function ug(){return rEsh;}())]((function EM" ascii
    $s16 = "turn ocF;}()) + (function TZdF(){return GN;}()) + MAqPq + (function J0(){return QuxD;}()) + Jz ? (function eL(){return EP;}()) +" ascii
    $s17 = "r nxcgL = LDrS[(function FPt(){return Tavu;}()) + wQ(WQ) + mASTp + (function eMih(){return eDq;}()) + aI(hTE) + (function eUdoc(" ascii
    $s18 = "ZcZ[PkmI + UYJK] = 1;VZcZ[GgNL(H1) + (function QU(){return ezY;}())](a[cnX(PPU) + (function FfYx(){return ZkLFX;}()) + O0(iMlLn)" ascii
    $s19 = "eturn l0;}()) + rFx(UxwsE) + (function dIby(){return EW;}()) + a0(AkIO) + gX(G1) + X0 + AP + Bxlc(HzRuz), false);a[qcbZ(OyEP) + " ascii
    $s20 = " (function Qr(){return fyq;}()) + (function VR(){return BtMNR;}()) : iwzU(qfmT) + KwpJ(lgNv) + bB + (function yELg(){return WqV;" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}