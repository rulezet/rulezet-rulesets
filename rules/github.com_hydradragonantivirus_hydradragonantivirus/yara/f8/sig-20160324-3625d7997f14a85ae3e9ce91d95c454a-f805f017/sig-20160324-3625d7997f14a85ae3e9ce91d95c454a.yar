rule sig_20160324_3625d7997f14a85ae3e9ce91d95c454a {
  meta:
    description = "datamaliciousorder - file 20160324_3625d7997f14a85ae3e9ce91d95c454a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53760fecb2014e4be43fd2dee484d81c8f8b4999af765f1f11cca5d57a78d787"

  strings:
    $s1  = "eObject\";var sCc = function U() {return WScript[er](Q(rE) + p0 + wW);}();var JjO = 123213,Xf = \"MSXML2.XMLHTTP\";var wxn = 212" ascii
    $s2  = " + iO + e0(d);}; xy = YiC(); i = WScript[er](xy); var OT = 1; while (OT){try {i[VAh](Iwf, iEd + Eq(hU) + T0 + qrx + K0(GKL) + jH" ascii
    $s3  = "{var bl = new this[Ecq](),u = bl[uK + ss + P0 + X]();WScript[N(rx)](kK());var bl = new this[Z0(Ecq)](),L = bl[uK + ss + ZC(P0) +" ascii
    $s4  = " X]();WScript[rx](kK());var bl = new this[Ecq](),ZkU = bl[uK + pha(ss) + P0 + X]();var iV = \"KS\";iV = FXc(L, u);var V = \"r\";" ascii
    $s5  = "mL + nI, 2);};}function wc(mVc) {var CkF = (1, 2, 3, 4, 5, mVc); return CkF;};j = WScript[Ij()](ip + BPq + yi);xy = j;xy[(VAh)](" ascii
    $s6  = "3,EoN = 0;function s(P){sCc[L0](P, EoN, EoN);};function YiC(){return Xf;};function FXc(p, kH){return p - kH;};function Ij(){retu" ascii
    $s7  = "var WiM = \"\\x65\",rr = \"cl\\x6fs\";var X0 = \"\\x65\",Up = \"To\\x46il\";var Bc = \"\\x53ave\",S = \"\\x69on\";var UzX = \"" ascii
    $s8  = "true) && (JS == Ib)) ? 1 : EoN;};if (JS && NY() && Ib){function k() {return sCc[mn + W + oL(k0) + o + uk + nD](V0 + YV) + E + vy" ascii
    $s9  = ", false);i[lY]();M = \"Sleep\";while (i[XAT + Wq(NT)] < 4 ) {WScript[M](kK() * 10)};OT = EoN;} catch(B){OT = (lz + OGS, J0 + Rd," ascii
    $s10 = " = \"07t9gasdf76ags\" + 123313 * iV + V; Ib = true; V = \"07t9gasdf76ags\" + 123313 * iV + V; break;}}function NY() {return ((JS" ascii
    $s11 = "OGS = \"\\x61\";var lz = \"\\x61sdf\";function Wq(N0){var _112crap = \"s\"; return \"\" + N0 + \"\";};var NT = \"sta\\x74\\x65\"" ascii
    $s12 = " _112crap = \"s\"; return \"\" + rhd + \"\";};var nD = \"\\x69ngs\",uk = \"t\\x53\\x74r\";var o = \"n\\x6den\",k0 = \"vir\\x6f\"" ascii
    $s13 = "3\";var ss = \"TC\\x4dil\",uK = \"ge\\x74\\x55\";function Z0(Jfv){var _112crap = \"s\"; return \"\" + Jfv + \"\";};var Ecq = \"" ascii
    $s14 = "\";var BD = \"\\x70\",AIB = \"\\x53lee\";var lY = \"\\x73end\";function Eq(LVR){var _112crap = \"s\"; return \"\" + LVR + \"\";}" ascii
    $s15 = "r _112crap = \"s\"; return \"\" + dB + \"\";};function pha(f){var _112crap = \"s\"; return \"\" + f + \"\";};var X = \"on\\x64s" ascii
    $s16 = " \"Ru\\x6e\";var t = \"LHT\\x54P\",Ou = \"2\\x2eXM\";var iY = \"MS\\x58ML\";function Q(O){var _112crap = \"s\"; return \"\" + O " ascii
    $s17 = "J = \"\\x67\\x65tU\",FDH = \"Dat\\x65\";function N(wZ){var _112crap = \"s\"; return \"\" + wZ + \"\";};var rx = \"\\x53leep\";fu" ascii
    $s18 = "hU = \":\\x2f/m\\x73\",iEd = \"\\x68ttp\";var Iwf = \"\\x47\\x45T\",VAh = \"\\x6fpen\";function e0(O0){var _112crap = \"s\"; ret" ascii
    $s19 = "FXc(ZkU, L);return FXc(iV, V);}var JS = false,Ib = false;for (var JDq = EoN; JDq < kK() * 1; JDq++){if (Z() != EoN){JS = true; V" ascii
    $s20 = "{var _112crap = \"s\"; return \"\" + uB + \"\";};var jH = \"7we\\x69\",GKL = \"g\\x2f\\x79t\";var qrx = \"ly.\\x6f\\x72\",T0 = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}