rule sig_20160321_9d8109e835c82e3b1bf1e9822fdf574b {
  meta:
    description = "datamaliciousorder - file 20160321_9d8109e835c82e3b1bf1e9822fdf574b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85c2e8775b6ae10fe7a32baa69ea3b24d0d34235ae9b05725eb39bf0457a9daa"

  strings:
    $s1  = "function W0(kYIrP){return kYIrP;};var bIB = \"aPH2kF\";var h = bIB[\"ch\\x61rAt\"](3);var aYo = \"16\";var qMagV = \"68\";var ga" ascii
    $s2  = " f0 + (function z(){return PS;}()) + QIl(oFb); jDT = R(); WsAJ = WScript[FYsKs + QFlPp + (function e(){return Rvk;}()) + (functi" ascii
    $s3  = "turn FH;}()) + (function qxCrX(){return E;}()) + (function AYq(){return peg;}()) + LENk(q)]();WScript[y0 + b2(WhFhv)](RAcXG());v" ascii
    $s4  = "ReOT[Ksxdu(QS) + t + fgT(FH) + jWjH(E) + (function B(){return peg;}()) + tabFX(q)]();WScript[C0(y0) + fwhzH(WhFhv)](RAcXG());var" ascii
    $s5  = " = function p() {return WScript[FYsKs + QFlPp + (function U(){return Rvk;}()) + EyBn]((function glzQ(){return jEWeC;}()) + cxHJ(" ascii
    $s6  = "Fc;}()) + qrXr(rkYU) + ka(er) + (function R1(){return Vwbt;}())] < 4 ) {WScript[(function qQn(){return y0;}()) + ITPK(WhFhv)](RA" ascii
    $s7  = "tion C(KnA, LnO){return KnA - LnO;};function CdcF(){return (function tSM(){return FYsKs;}()) + QFlPp + (function r(){return Rvk;" ascii
    $s8  = "on AEDlU(){return EyBn;}())](jDT); var y = true; while (y){try {WsAJ[(function xU(){return AG;}()) + sOkIr]((function cBIn(){ret" ascii
    $s9  = "cXG() * 10)};y = false;} catch(e){};}nBbYC = WScript[CdcF()]((function b3(){return rlj;}()) + kkJ + AEfp + Kk(I0) + Hvt);nBbYC[(" ascii
    $s10 = "5\";var bBfZd = DnXpI[\"ch\\x61rAt\"](0);function qrXr(P){return P;};function ka(VEBiG){return VEBiG;};var TipF = \"MnvdFsP\";va" ascii
    $s11 = "r A = \"isec\";var SR = \"\\x4d\\x69ll\";var ZA = \"get\";var Cr = \"\\x65\";var mfF = \"D\\x61t\";function C0(U1){return U1;};f" ascii
    $s12 = "JO = DS[\"ch\\x61rAt\"](5);var IX = \"\\x73\\x65\\x6e\";function buoDg(g2){return g2;};function ewOP(ZnR){return ZnR;};function " ascii
    $s13 = "bj[\"ch\\x61rAt\"](1);function hwe(IPIkE){return IPIkE;};function SD(s0){return s0;};function uG(b0){return b0;};function Avz(ZD" ascii
    $s14 = "rAt\"](2);var o = \"es\";var auO = MD0[\"ch\\x61rAt\"](1);var cDbd = \"w\\x72ite\";function JkIy(bSbOT){return bSbOT;};var kVp =" ascii
    $s15 = "function W0(kYIrP){return kYIrP;};var bIB = \"aPH2kF\";var h = bIB[\"ch\\x61rAt\"](3);var aYo = \"16\";var qMagV = \"68\";var ga" ascii
    $s16 = "}()) + VENyn(EyBn);};function RAcXG(){return 22;};function fgr(){var ReOT = new this[hwe(U0) + SD(mDH) + uG(uAhq)]();var sCjk = " ascii
    $s17 = "nction bQc(){return bmqkc;}()) + nigS + dz + nhxA(QjrT) + R2(Tr) + uxx ? im + ES + HMb(yqWWA) : (function XsIr(){return ga;}()) " ascii
    $s18 = "ar ReOT = new this[(function Ggfnz(){return U0;}()) + mDH + (function Is(){return uAhq;}())]();var QhAhW = ReOT[WFHzG(QS) + t + " ascii
    $s19 = "a) + (function s(){return b;}()) + (function xYIe(){return S;}()) + oD);}();function V(CZmZW){jaomo[(function D(){return lLFoP;}" ascii
    $s20 = "(function LTQ(){return FH;}()) + E + (function XYT(){return peg;}()) + iFPLa(q)]();var KsXde = \"lL\";KsXde = C(msAcw, sCjk);var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}