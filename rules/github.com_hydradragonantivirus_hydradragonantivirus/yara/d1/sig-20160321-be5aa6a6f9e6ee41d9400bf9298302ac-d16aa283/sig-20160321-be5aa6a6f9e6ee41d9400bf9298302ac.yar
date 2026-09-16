rule sig_20160321_be5aa6a6f9e6ee41d9400bf9298302ac {
  meta:
    description = "datamaliciousorder - file 20160321_be5aa6a6f9e6ee41d9400bf9298302ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "551ba79802230fe8b9456f5ca8fe864c3fa40a11e6d18e675e8e098fc6b63476"

  strings:
    $s1  = "function LPTT(J0){return J0;};var fk = \"u42QZ5\";var sD = \"62\";var SZu = \"1\";var v2 = \"1\\x38368\";var tw = fk[\"charAt\"]" ascii
    $s2  = "();var nH = woBp[(function F(){return unPX;}()) + wuDlJ(di) + u0(KMvb) + (function q0(){return Yl;}()) + wCD(WEMr)]();WScript[SE" ascii
    $s3  = "2 + (function Uddq(){return HYr;}()); kOIg = ZIGi(); ajlVA = WScript[K + Gh(q) + ndY(WaDh) + Z0(Mjhi)](kOIg); var XlzGh = true; " ascii
    $s4  = " WEMr;}())]();WScript[(function vkr(){return SE;}()) + (function f1(){return mZiT;}())](dF());var woBp = new this[Dap(hH0) + gW]" ascii
    $s5  = "jhi = \"ect\";var WaDh = \"\\x6a\";var q = \"\\x74e\\x4fb\";var K = \"Crea\";var nyh = function IM() {return WScript[MrtrG(K) + " ascii
    $s6  = " + k(xcLMd) + (function rHBl(){return CX;}()) + Rwun(EeQ) + ZBMi(ey);};function GZnw(Rf, D){return Rf - D;};function MerZ(){retu" ascii
    $s7  = "ehL;}())]();while (ajlVA[Dwg(jdVs) + c(GPxJ) + C0(nn)] < 4 ) {WScript[izt(SE) + s(mZiT)](dF() * 10)};XlzGh = false;} catch(e){};" ascii
    $s8  = "}pfbIC = WScript[MerZ()](eh(K0) + CASh(efY) + bYz(L) + (function wupf(){return laDF;}()));pfbIC[((function PmTJU(){return Fn;}()" ascii
    $s9  = "ion LOXDm(BzQp){return BzQp;};var Cc = \"jf8XhavB\";var vW = \"f\";var WYuj = \"s\\x64\";var YZt = \"uhi\";var u1 = Cc[\"charAt" ascii
    $s10 = "ST;};function Rwun(JFlyg){return JFlyg;};function ZBMi(IBvxK){return IBvxK;};var lFP = \"mP2lMi\";var ey = lFP[\"charAt\"](1);va" ascii
    $s11 = "IBmK = \"ant\\x65\\x63\";var yUPt = \"\\x61\\x76\";var ZN = YYl[\"charAt\"](1);var EaXl = \"\\x74p\\x3a/\";var hu = \"ht\";funct" ascii
    $s12 = "ction m0(Am){return Am;};var li = \"Q1%RxGd\";var GtTA = \"%/\";var KlnA = \"T\\x45MP\";var Kz = li[\"charAt\"](2);function fCQR" ascii
    $s13 = "function LPTT(J0){return J0;};var fk = \"u42QZ5\";var sD = \"62\";var SZu = \"1\";var v2 = \"1\\x38368\";var tw = fk[\"charAt\"]" ascii
    $s14 = "dVs = \"re\\x61\";var mkj = \"Ulslq2m\";var LWehL = \"en\\x64\";var tS = mkj[\"charAt\"](2);function fyMu(sT){return sT;};functi" ascii
    $s15 = "ction C(sXeD){return sXeD;};var KPz = \"XLY8FlMGMzb\";var d = KPz[\"charAt\"](5);var WPWG = \"Shel\";var wHXLm = \"i\\x70t.\";va" ascii
    $s16 = "n Xo;}()) + HBB + (function fQVlQ(){return t0;}()) + kpnmF(G0) + iYa + (function ib(){return izn;}()) + (function PNow(){return " ascii
    $s17 = "(function f0(){return WaDh;}()) + (function SI(){return Mjhi;}())]((function wB(){return IkXYw;}()) + LBIp(wHXLm) + C(WPWG) + d)" ascii
    $s18 = "agnfJ](Oxuk(Kz) + sFbol(KlnA) + m0(GtTA)) + (function AgW(){return CPcN;}()) + (function mhEwB(){return YbIy;}()) + rBu + gg + f" ascii
    $s19 = "rn (function lkN(){return K;}()) + u(q) + vr(WaDh) + a(Mjhi);};function dF(){return 22;};function auYGi(){var woBp = new this[hH" ascii
    $s20 = " mXMw;}()) + (function P(){return ZVtFd;}()) + jFz(ZCMsi) : tw + (function bOJnM(){return v2;}()) + (function inoqz(){return SZu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}