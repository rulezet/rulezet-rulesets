rule sig_20160324_df72f78a8a294de63858f2dfcfc25ac4 {
  meta:
    description = "datamaliciousorder - file 20160324_df72f78a8a294de63858f2dfcfc25ac4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d70d39e631169285b354b9c1a5470ece0ce641d1a8eaebe1fe46d7bea007a2df"

  strings:
    $s1  = "ect\";var vyU = function w() {return WScript[kqI](g0(wsN) + SV + Y);}();var g = 123213,m = \"MSXML2.XMLHTTP\";var BDa = 2123213," ascii
    $s2  = "e(){var q = new this[NF](),wB = q[Puu(OO) + BRF + L0 + jAb(wrz)]();WScript[fg(CCl) + S(F)](WzV());var q = new this[NF](),wus = q" ascii
    $s3  = "[qMG(OO) + BRF + Ial(L0) + wrz]();WScript[CCl + F](WzV());var q = new this[NF](),YL = q[OO + BRF + n(L0) + wrz]();var raU = \"jK" ascii
    $s4  = " yX = (1, 2, 3, 4, 5, We); return yX;};C = WScript[NS()](qpv + KC + SlG(C0));dba = C;dba[(pC)]();dba[Zi] = om(1);dba[cWc(uxz) + " ascii
    $s5  = " = 0;function hAE(EG){vyU[To](EG, TeJ, TeJ);};function h(){return m;};function c(wv, e0){return wv - e0;};function NS(){return k" ascii
    $s6  = "var cCr = \"c\\x6cose\",aCk = \"o\\x46ile\";var oX = \"\\x53a\\x76eT\",MO = \"t\\x69\\x6fn\";var Fjc = \"p\\x6fsi\";function iV(" ascii
    $s7  = "+ XIO; break;}}function L() {return ((vB == true) && (vB == BU)) ? 1 : TeJ;};if (vB && L() && BU){function GT() {return vyU[ps +" ascii
    $s8  = "ZA[pdA + KK + I0(kk)] < 4 ) {WScript[gHG](WzV() * 10)};w0 = TeJ;} catch(t){w0 = (PK, l + mxE, K + cH, 2);};}function om(We) {var" ascii
    $s9  = "r l = \"f\\x61d\\x66\",PK = \"a\\x73dfa\";function I0(Fc){var _112crap = \"s\"; return \"\" + Fc + \"\";};var kk = \"\\x74e\",KK" ascii
    $s10 = " pdA = \"re\\x61d\",Uy = \"\\x70\";var TvG = \"Sle\\x65\";function POp(Mwx){var _112crap = \"s\"; return \"\" + Mwx + \"\";};var" ascii
    $s11 = "TxD = \"\\x39P\\x6f9\",eBW = \"\\x7at\\x52m9\";var HL = \"\\x4fLr\\x50t\";function Pct(j2){var _112crap = \"s\"; return \"\" + j" ascii
    $s12 = ";raU = c(wus, wB);var XIO = \"Znz\";XIO = c(YL, wus);return c(raU, XIO);}var vB = false,BU = false;for (var j = TeJ; j < WzV() *" ascii
    $s13 = " = \"s\"; return \"\" + gXD + \"\";};var N = \"B\\x6fdy\",JH = \"o\\x6e\\x73\\x65\";var SM = \"Res\\x70\";function cWc(d){var _1" ascii
    $s14 = "n \"\" + nj + \"\";};function jAb(QSq){var _112crap = \"s\"; return \"\" + QSq + \"\";};function qMG(G){var _112crap = \"s\"; re" ascii
    $s15 = "+ \"\";};function Ial(sZE){var _112crap = \"s\"; return \"\" + sZE + \"\";};function n(QSA){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = "{var _112crap = \"s\"; return \"\" + AX + \"\";};function Pze(wK){var _112crap = \"s\"; return \"\" + wK + \"\";};function wYA(E" ascii
    $s17 = "urn \"\" + d + \"\";};var Er = \"\\x65\",uxz = \"w\\x72i\\x74\";var Zi = \"ty\\x70e\",h0 = \"ope\\x6e\";function SlG(M){var _112" ascii
    $s18 = "rap = \"s\"; return \"\" + Ej + \"\";};function Ofs(O){var _112crap = \"s\"; return \"\" + O + \"\";};var nig = \"x\\x65\",nSN =" ascii
    $s19 = "x79\";var wRs = \"ht\\x74p\";function lX(V){var _112crap = \"s\"; return \"\" + V + \"\";};var o = \"\\x47ET\",pC = \"o\\x70en\"" ascii
    $s20 = "lis\\x65\",j0 = \"\\x54CM\\x69\";var pE = \"g\\x65\\x74U\",tW = \"\\x44ate\";function fg(GT0){var _112crap = \"s\"; return \"\" " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}