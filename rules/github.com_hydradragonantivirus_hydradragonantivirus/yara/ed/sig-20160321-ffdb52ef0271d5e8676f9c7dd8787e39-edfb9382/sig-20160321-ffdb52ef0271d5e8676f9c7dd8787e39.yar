rule sig_20160321_ffdb52ef0271d5e8676f9c7dd8787e39 {
  meta:
    description = "datamaliciousorder - file 20160321_ffdb52ef0271d5e8676f9c7dd8787e39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fade3bd7a3f1e077ab0bad701383bb441ce2a7076ea6af9f9b203313e4cc0f3"

  strings:
    $s1  = "function SVeKR(u){return u;};var e0 = \"2\";var iMYyb = \"68\\x316\";var vSGO = \"2183\";function n0(VZ){return VZ;};var gbuD = " ascii
    $s2  = "ar KBk = new this[V]();var oU = KBk[ttC + xd + mItv + i(cH) + (function hlMcd(){return Fz;}())]();WScript[(function DOmh(){retur" ascii
    $s3  = "KDib(){return Rpo;}()) + (function aT(){return iNCU;}())]();while (h[HFy + yK + A0 + R(aEvP)] < 4 ) {WScript[jxuT(EG)](BwCmT() *" ascii
    $s4  = "(function Lv(){return o;}()); idT = hPrCE(); h = WScript[NzT(HNU) + (function wbi(){return Niy;}()) + e(Cxxh) + aIFX(Lyfqe) + bW" ascii
    $s5  = " 22;};function XG(){var KBk = new this[V]();var srni = KBk[ttC + pOAA(xd) + cJk(mItv) + cH + V0(Fz)]();WScript[f(EG)](BwCmT());v" ascii
    $s6  = ") + C + aQtK + (function l(){return Ug;}()) + (function LkL(){return cCd;}());};function Vov(q, wuIz){return q - wuIz;};function" ascii
    $s7  = "var j = 0; j < BwCmT() * 1; j++){if (XG() != 0){IZLP = true;yC = true;break;}}function UFGs() {return IZLP && yC;};if (UFGs()){g" ascii
    $s8  = "yfqe = \"je\\x63\";var Cxxh = \"ate\\x4f\\x62\";var Niy = \"re\";var HNU = hjW[\"c\\x68arA\\x74\"](0);var Pg = function tKG() {r" ascii
    $s9  = " 10)};GBiq = false;} catch(e){};}NDia = WScript[UKS()](a + (function yqk(){return XbN;}()) + (function K(){return OoyAE;}()) + (" ascii
    $s10 = "fam\";var vrmMS = \"//\\x7a\";var gybUC = \"h\\x74\\x74\\x70:\";function I(PB){return PB;};var LvbL = \"GET\";function Abik(kJje" ascii
    $s11 = " UKS(){return (function n(){return HNU;}()) + fW(Niy) + Cxxh + (function N(){return Lyfqe;}()) + bWlfh;};function BwCmT(){return" ascii
    $s12 = " HcvPA;}()) + GxY + (function LNIs(){return weW;}()) + AY(MGmnE) + (function qI(){return fF;}())](fmBaz + (function fVaaZ(){retu" ascii
    $s13 = "lfh](idT); var GBiq = true; while (GBiq){try {h[(function Xf(){return qc;}())](I(LvbL), (function G0(){return gybUC;}()) + (func" ascii
    $s14 = "+ (function ZpNk(){return NkTiQ;}()) + (function DMjc(){return Te;}()) + (function EpSQ(){return Xapl;}()), false);h[(function S" ascii
    $s15 = ") + (function Tr(){return GdWka;}())] = 1;NDia[(function fywyw(){return NJpI;}()) + ZfuFG](h[ymox + zSdaV(qGd) + (function nReTk" ascii
    $s16 = "(){return aIQx;}()) + ZlpUW]);NDia[A1 + ApY + (function T0(){return gJVe;}())] = 0;NDia[fZMl(iHfPF) + Ong + NZ](gMo, 2 );NDia[hY" ascii
    $s17 = "[HNU + Niy + fk(Cxxh) + (function t(){return Lyfqe;}()) + (function QgdPR(){return bWlfh;}())](sfF + (function fJBHH(){return wc" ascii
    $s18 = "n EG;}())](BwCmT());var KBk = new this[V]();var kDWY = KBk[cc(ttC) + xd + QNSzZ(mItv) + cH + (function tGKw(){return Fz;}())]();" ascii
    $s19 = "DL) + IZLP ? (function IDgHW(){return tTC;}()) + MUrzy + n0(V1) : SVeKR(vSGO) + iMYyb + (function mybaO(){return e0;}());}" fullword ascii
    $s20 = "B;}()) + yw(Ad) + (function dwOcJ(){return weolI;}()));}();function HKq(LP){Pg[WuaMl](LP, 0, 0);};function hPrCE(){return wv(FJu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}