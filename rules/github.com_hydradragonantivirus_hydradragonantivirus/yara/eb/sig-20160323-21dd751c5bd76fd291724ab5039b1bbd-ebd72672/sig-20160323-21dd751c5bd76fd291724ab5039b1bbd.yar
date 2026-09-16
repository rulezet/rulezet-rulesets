rule sig_20160323_21dd751c5bd76fd291724ab5039b1bbd {
  meta:
    description = "datamaliciousorder - file 20160323_21dd751c5bd76fd291724ab5039b1bbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ede7f9ae3c74e273ae6ab5523871e6f107274cbf98a9c2ce505a58e7ecf629d6"

  strings:
    $s1  = "function sFe(pGv){var _112crap = \"s\"; return \"\" + pGv + \"\";};function E2(M2){var _112crap = \"s\"; return \"\" + M2 + \"\"" ascii
    $s2  = "e);};}function mU(y) {var tC = (1, 2, 3, 4, 5, y); return tC;};m = (ZK) ? 14134 : 414234;Tjf = WScript[b()](B2(ofQ) + v2(OZ) + M" ascii
    $s3  = "= \"bjec\\x74\",nom = \"teO\";var st = \"a\",wDJ = \"re\";var FVk = \"\\x43\",Pu = false;var djG = function OKq() {return WScrip" ascii
    $s4  = "nQ = WScript[fax(FVk) + wDJ + st + Mes(nom) + HCZ(tZ)](L); var B = true; while (B){try {snQ[DZ(xL)](c, Ef(Fj) + HfS(UZw) + YeL(q" ascii
    $s5  = "WScript[ge(jw)](Oxx());var hv = new this[pV](),NYD = hv[Uc + Pm(N) + E + uK(Vb) + Yfg + ptb(tLN)]();WScript[jw](Oxx());var hv = " ascii
    $s6  = " wzT + \"\";};var nj = \"D79EFolK\",z0 = \"Fil\\x65\";var S4 = nj[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](5),SR = \"Sa\\x76\\x65" ascii
    $s7  = "65\\x76\",Fj = \"\\x68ttp\\x3a\";var c = \"GET\";function DZ(GrD){var _112crap = \"s\"; return \"\" + GrD + \"\";};function x(Sm" ascii
    $s8  = "XMLHT\",v = \"\\x4dL2.\";var yQI = lW[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](4),iUb = \"M\\x53\";function MUo(S0){var _112crap " ascii
    $s9  = ";var ux = t[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](1),wGy = \"W\";function M(Ib){var _112crap = \"s\"; return \"\" + Ib + \"\";" ascii
    $s10 = " 0, 0);};function jJi(){return X(iUb) + S1(yQI) + TU(v) + sVd + k(v0);};function wQI(cHy, Rm){return cHy - Rm;};function b(){ret" ascii
    $s11 = "& (ZK == true)) ? true : false;};if (ZK && NF() && gTb){function AnR() {return djG[xMU(uFy) + MOT(exe) + mc(Brp) + Y0(CcU) + PCU" ascii
    $s12 = "ne(ze)] < 4 ) {WScript[jw](Oxx() * 10)};B = false;} catch(fw){B = (U0 + RxZ(DHn), l2 + lKE(M1), Qt(tl) + icO(zQy) + QPo(w0), tru" ascii
    $s13 = "ar UNr = \"\\x74\",aSb = WOg[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](0);var qfb = \"os\",Wy = \"\\x70\";function t1(gy){var _112" ascii
    $s14 = "};var CGZ = \"QlyXUJv\",GP = CGZ[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](2);var va = \"Bod\",fl = \"\\x70o\\x6ese\";var pgm = \"" ascii
    $s15 = "\\x55\\x54CMi\";var Uc = \"g\\x65\\x74\";function oIk(dfb){var _112crap = \"s\"; return \"\" + dfb + \"\";};function gVZ(DkV){va" ascii
    $s16 = "R = \"t\\x79\\x70e\",Pu0 = \"GsuYnK5e\";var hz = Pu0[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"rAt\"](4),aJV = \"pe\";var w1 = \"o\";func" ascii
    $s17 = "\\x44at\\x65\";function ge(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};var jw = \"Sleep\";function eOw(su){var _112crap " ascii
    $s18 = "\"\" + oY + \"\";};function S(bGG){var _112crap = \"s\"; return \"\" + bGG + \"\";};function Ov(HU){var _112crap = \"s\"; return" ascii
    $s19 = "rn \"\" + pa + \"\";};function UW(Enf){var _112crap = \"s\"; return \"\" + Enf + \"\";};function ojl(tk){var _112crap = \"s\"; r" ascii
    $s20 = "n 22;};var m = 0,uf = 0;function soH(){var hv = new this[oIk(pV)](),HQ = hv[eOw(Uc) + C(N) + YlD(E) + RQg(Vb) + r(Yfg) + tLN]();" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}