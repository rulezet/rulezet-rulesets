rule sig_20160321_af31815c06d2ef9b47ce8ad31cf2b090 {
  meta:
    description = "datamaliciousorder - file 20160321_af31815c06d2ef9b47ce8ad31cf2b090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e548ad59bdf81c98d198d8093b728d2e6067eb3d9862f5f94a57f35bf61c5fd1"

  strings:
    $s1  = "function PTv(GPZQc){return GPZQc;};function STnBS(A1){return A1;};var Ss = \"8162\";var u2 = \"1836\";var ztM = \"2\";function r" ascii
    $s2  = "\\x65O\\x62j\";var L0 = \"\\x65\\x61\";var hXqY = \"Cr\";var igB = function e() {return WScript[l(hXqY) + (function ewqY(){retur" ascii
    $s3  = "L) + XYMB(Kfsnd) + LLpXM + QNL(YLJV)]();WScript[(function QoL(){return m0;}()) + YHQa(cdm) + pzUYa](I());var yth = new this[ND](" ascii
    $s4  = " + AafV(S), false);wfrR[Tn(yG) + aopyY(W1)]();while (wfrR[fauCW(ov) + SXL + e0 + FQs(KAE) + u] < 4 ) {WScript[bP(m0) + pNjCc(cdm" ascii
    $s5  = ");var lp = yth[(function fSl(){return cL;}()) + Kfsnd + (function cyB(){return LLpXM;}()) + fgr(YLJV)]();WScript[yPBtv(m0) + Otw" ascii
    $s6  = "wfrR = WScript[(function mbDy(){return hXqY;}()) + L0 + (function Ec(){return ZC;}()) + sv(iHWE) + kHi](cNo); var yQp = true; wh" ascii
    $s7  = "f(aOAk) + EFINq(Y);};function sYSLH(Hg, m){return Hg - m;};function jple(){return hXqY + Izr(L0) + ZC + iHWE + (function sg(){re" ascii
    $s8  = "= true;break;}}function uSDfo() {return HG && gtesp;};if (uSDfo()){fstam = igB[(function LHB(){return GlB;}()) + fMX(nShOV) + (f" ascii
    $s9  = ") + RRTi(pzUYa)](I() * 10)};yQp = false;} catch(e){};}Pa = WScript[jple()]((function XgW(){return GdXbv;}()) + ZoD + UHx(A0));Pa" ascii
    $s10 = "\"a\\x72a\";var yGLmT = \"//\\x64iv\";var VB = \"\\x68\\x74tp:\";function FtG(UO){return UO;};var CEvfC = \"\\x47ET\";function U" ascii
    $s11 = "vR;};function PvZ(sJb){return sJb;};var YLJV = \"\\x64\\x73\";var LLpXM = \"s\\x65c\\x6fn\";var Kfsnd = \"i\\x6c\\x6c\\x69\";var" ascii
    $s12 = "(function QyW(){return u0;}()) + (function FoG(){return n1;}())] = 0;Pa[zJi + (function ADTkc(){return D;}()) + (function G(){re" ascii
    $s13 = ";}())](qqRrM, 0, 0);};function g(){return (function Lkqe(){return vax;}()) + rLmPe + t + (function fgwK(){return XlIn;}()) + Zgy" ascii
    $s14 = "eturn sYSLH(L, zAIXa);}var HG = false;var gtesp = false;for (var aMO = 0; aMO < I() * 1; aMO++){if (ays() != 0){HG = true;gtesp " ascii
    $s15 = "turn dF;}()) + jKsHp(oejME)](fstam, 2 );Pa[ou(SMte) + (function uxWS(){return FwnYE;}())]();p(fstam);L = \"\" + TA + daPGe + (fu" ascii
    $s16 = "g(tHa) + BUbx + zNxFs(dYVA) + yic(hm) + (function sE(){return mcGZW;}()) + (function M0(){return biPZb;}()) + VtF + HG ? r1(S0) " ascii
    $s17 = "(cdm) + (function V(){return pzUYa;}())](I());var yth = new this[(function z(){return ND;}())]();var Pxv = yth[WlqBd(cL) + PvZ(K" ascii
    $s18 = "fsnd) + (function HfMqk(){return LLpXM;}()) + YLJV]();var L = \"zU\";L = sYSLH(lp, A);var zAIXa = \"aAUzG\";zAIXa = sYSLH(Pxv, l" ascii
    $s19 = "tion dH(){return sG;}()) + Hg0(IuMU) + m1(Uo) + (function Xhy(){return BY;}()) + (function u1(){return LtllV;}()) + WYZ(sx) + wd" ascii
    $s20 = " + (function TE(){return ZC;}()) + bCQk(iHWE) + (function uWWKg(){return kHi;}())](H0 + (function HEtl(){return uIqX;}()) + (fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}