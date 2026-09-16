rule sig_20160321_0f80de2492063164b43bbe9a1a41ebaf {
  meta:
    description = "datamaliciousorder - file 20160321_0f80de2492063164b43bbe9a1a41ebaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ad7ef0a5445ec4264762e2d07ef8106d192e4ccf41f351ef4e833ece1042a5a"

  strings:
    $s1  = "function JW(DBou){return DBou;};function nMj(cC){return cC;};function LZKvV(dvzeZ){return dvzeZ;};var p1 = \"172c23nG\";var jKp " ascii
    $s2  = "new this[(function fQ(){return D;}())]();var l1 = PJRA[zt(H) + pi(qUjj) + HaQo(Swf) + (function atpZ(){return p;}())]();WScript[" ascii
    $s3  = "n N() {return WScript[lkCU + e(Op) + (function yf(){return pmZ;}()) + (function ULSJX(){return UTJ;}())](WT(HBQ) + (function e0(" ascii
    $s4  = "()) + (function KudBT(){return LDvSO;}()) + lLxl] < 4 ) {WScript[(function Vtu(){return DsTtN;}()) + (function r0(){return ZjEM;" ascii
    $s5  = "turn Ok;}()) + (function ZSSwF(){return l2;}()); uKk = BVtu(); jcMx = WScript[uG(lkCU) + (function aT(){return Op;}()) + (functi" ascii
    $s6  = "Q(qUjj) + wkiSi(Swf) + p]();WScript[(function kVg(){return DsTtN;}()) + ZjEM + (function p0(){return dJ;}())](wlV());var PJRA = " ascii
    $s7  = "EdZb(NB, FR){return NB - FR;};function l0(){return lkCU + (function Y(){return Op;}()) + (function AVcfr(){return pmZ;}()) + UdU" ascii
    $s8  = "return YVxe && qL;};if (Jd()){YHTA = sYC[bOb(DZ) + qCEEm + kvDT(b) + (function xaUE(){return UBunm;}()) + MdSs + OZLjU + T0(yl) " ascii
    $s9  = "}()) + (function HUtVc(){return dJ;}())](wlV() * 10)};lTnJ = false;} catch(e){};}GIMV = WScript[l0()](yyKs(X) + (function aSvEj(" ascii
    $s10 = "on WkZ(wbcP){return wbcP;};var SRQg = \"cuHxW\";var ohz = \"8qlzLy\";var j = ohz[\"charAt\"](2);var Fo = \"S\\x68el\";var FQTsT " ascii
    $s11 = "TaiiI = \"po\\x73it\";function GtimD(e1){return e1;};var oJyzY = \"47yhrWb\";var Ep = oJyzY[\"charAt\"](2);var H0 = \"\\x73eBod" ascii
    $s12 = "gR = \"wKRh\";var jQ = \"un\";var Faw = UgR[\"charAt\"](2);function WT(znsKc){return znsKc;};function hkJ(BrwBS){return BrwBS;};" ascii
    $s13 = "lxg;};function RijV(g){return g;};var Ih = \"QMNtlI\";var qD = \"ype\";var B0 = Ih[\"charAt\"](3);var nsj = \"\\x6fpen\";functio" ascii
    $s14 = "turn ZxyDR;};var Dp = \"jeoUvtS\";var UTJ = Dp[\"charAt\"](5);var pmZ = \"Objec\";var Op = \"te\";var lkCU = \"Cr\\x65a\";var sY" ascii
    $s15 = "\"2\";var hq = \"8\\x316\";var nN = \"36\";var XLnR = \"1\\x38\";var yq = p1[\"charAt\"](4);function kf(svg){return svg;};functi" ascii
    $s16 = "EsB = vGnB[\"charAt\"](0);var ypk = \"\\x65\\x61\\x74e\";var V = \"\\x43r\";function DyPA(jCR){return jCR;};function lt(RaxSh){r" ascii
    $s17 = "r Ev = \"Sc\\x72\\x69p\";var HBQ = SRQg[\"charAt\"](4);function e(Ibb){return Ibb;};function UdUPF(d){return d;};function uG(Zxy" ascii
    $s18 = "65\";var dvWxD = \"\\x53aveT\";function wX(ztH){return ztH;};var Moaq = \"0OMWun\";var HxMJ = Moaq[\"charAt\"](5);var Qfo = \"i" ascii
    $s19 = "4\";var IChmp = \"qi\\x59A\";var q0 = \"bE1d\";var Tb = \"MP%\\x2f\";var XKLl = q0[\"charAt\"](1);var pGPr = \"%\\x54\";function" ascii
    $s20 = "on q(){return pmZ;}()) + UTJ](uKk); var lTnJ = true; while (lTnJ){try {jcMx[(function ssoxG(){return G0;}()) + (function eaijr()" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}