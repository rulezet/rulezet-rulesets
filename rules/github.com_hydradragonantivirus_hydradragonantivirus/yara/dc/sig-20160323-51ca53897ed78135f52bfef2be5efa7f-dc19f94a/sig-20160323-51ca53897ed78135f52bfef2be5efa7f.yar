rule sig_20160323_51ca53897ed78135f52bfef2be5efa7f {
  meta:
    description = "datamaliciousorder - file 20160323_51ca53897ed78135f52bfef2be5efa7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f77a4b7f7fe7a7365349c4b89d5295dc92ad4af274fd48c0e702263a5f1348f"

  strings:
    $s1  = "function Yb(dm){var _112crap = \"s\"; return \"\" + dm + \"\";};function Ca(HN){var _112crap = \"s\"; return \"\" + HN + \"\";};" ascii
    $s2  = " \"s\"; return \"\" + pQP + \"\";};var Zn = \"%/\",hx = \"%TEMP\";function nbt(qJE){var _112crap = \"s\"; return \"\" + qJE + \"" ascii
    $s3  = "ion Io(){var EtL = new this[YU(hjD)](),ejw = EtL[jz(Gol) + cSH + aMU(S) + EX + xsN(tml) + EAa(X) + n0(y) + jD + R]();WScript[U(y" ascii
    $s4  = "i) + ML(Nv) + Ipb + WIU(Ctw);}; V = jV(); LbP = WScript[im + cGz + PGC(UGD) + MR(dEB)](V); var yAR = true; while (yAR){try {LbP[" ascii
    $s5  = "Script[nRO(y0) + JN + Jxy(Jwb)](Mgm());var EtL = new this[Pri(hjD)](),yV = EtL[rHL(Gol) + cSH + SA(S) + jK(EX) + Qn(tml) + X + y" ascii
    $s6  = "EB = \"\\x6a\\x65ct\",UGD = \"t\\x65O\\x62\";var cGz = \"a\",im = \"Cre\";var v = false,Xd = function B() {return WScript[im + V" ascii
    $s7  = "s\"; return \"\" + O1 + \"\";};var Ex = \"6fnlD\",P0 = \"Dqt6UXbD\";var bX = \"s\",Aku = \"\\x72\\x69ng\";var Wn = P0[\"c\"+\"" ascii
    $s8  = "UkD\",vGe = JD[\"c\"+\"\\x68\"+\"arAt\"](0);var OF = \"s\",IpF = \"c\\x6co\";function VTP(RJe){var _112crap = \"s\"; return \"\"" ascii
    $s9  = "\"\" + Srm + \"\";};function Nw(xN){var _112crap = \"s\"; return \"\" + xN + \"\";};var Sr = \"hv9GeFj1\",U1 = Sr[\"c\"+\"\\x68" ascii
    $s10 = "RD + \"\";};var ZOY = \"HoGtfnWbK\",HE = ZOY[\"c\"+\"\\x68\"+\"arAt\"](4);var kkF = \"dfasd\",m = \"fa\";function fD(l1){var _11" ascii
    $s11 = "\"B.S\";var WeU = \"ADOD\";function T0(EDl){var _112crap = \"s\"; return \"\" + EDl + \"\";};var Kk = \"ahfW4\",GLu = Kk[\"c\"+" ascii
    $s12 = "\"s\"; return \"\" + iF + \"\";};var MHc = \"dTGW\",xNZ = MHc[\"c\"+\"\\x68\"+\"arAt\"](0);var K0 = \"se\\x6e\";function pLN(F1)" ascii
    $s13 = "c\"+\"\\x68\"+\"arAt\"](2);function jF(Y1){var _112crap = \"s\"; return \"\" + Y1 + \"\";};var Dj = \"un\",nH = \"\\x52\";functi" ascii
    $s14 = " return \"\" + r + \"\";};var MF = \"Z7ennyhSO\",R = \"d\\x73\";var jD = MF[\"c\"+\"\\x68\"+\"arAt\"](4),y = \"\\x6f\";var X = " ascii
    $s15 = " + A0(CXQ) + QkW + BBQ(G) + pOL(geC) + d;};function gAm(Wfm, LjE){return Wfm - LjE;};function z(){return SQg(im) + cGz + la(UGD)" ascii
    $s16 = "\"07t9gasdf76ags\" + 123313 * YJG + kXF; break;}}function F() {return ((OV == wRV) && (OV == true)) ? true : false;};if (OV && F" ascii
    $s17 = " && wRV){function c() {return Xd[Avz + nbt(a) + Eb(v1) + irT(o1) + S0(d0) + Wn + O0(Aku) + E0(bX)](w(hx) + Zn) + O2 + M0 + TNO(w" ascii
    $s18 = "();while (LbP[dkf(Hja) + Nw(Vg) + U1] < 4 ) {WScript[Fqo(y0) + JN + O(Jwb)](Mgm() * 10)};yAR = false;} catch(Y){yAR = (fD(Nf) + " ascii
    $s19 = "KFpQEeBX\",Y3 = \"Adn\";var FM = Y3[\"c\"+\"\\x68\"+\"arAt\"](2),Z = \"o\";var NjH = \"ositi\",s = y1[\"c\"+\"\\x68\"+\"arAt\"](" ascii
    $s20 = "turn \"\" + l1 + \"\";};function cu(oJA){var _112crap = \"s\"; return \"\" + oJA + \"\";};function lB(GIR){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}