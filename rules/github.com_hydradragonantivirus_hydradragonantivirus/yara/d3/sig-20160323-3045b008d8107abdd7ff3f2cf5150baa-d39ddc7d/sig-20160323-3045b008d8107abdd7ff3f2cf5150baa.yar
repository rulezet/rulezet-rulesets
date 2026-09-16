rule sig_20160323_3045b008d8107abdd7ff3f2cf5150baa {
  meta:
    description = "datamaliciousorder - file 20160323_3045b008d8107abdd7ff3f2cf5150baa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf20107107fcb151681f9c5e6bb6d8de3de243cef4db7c23b61441b69a88825f"

  strings:
    $s1  = "function GM(P3){var _112crap = \"s\"; return \"\" + P3 + \"\";};function W3(u){var _112crap = \"s\"; return \"\" + u + \"\";};va" ascii
    $s2  = ";var bi = \"\\x25/\",W1 = \"%TEMP\";function Dj(h){var _112crap = \"s\"; return \"\" + h + \"\";};function JhX(e0){var _112crap " ascii
    $s3  = "var z = new this[BGu(nqq) + s(I0)](),hd = z[b0(H) + xg(V0) + J0(Af) + W0(I1) + tga(Is) + f(fQ) + J]();WScript[jw(EkZ) + s0(Ne) +" ascii
    $s4  = " = WScript[QdU + k(EIs) + NF(qiG)](OF); var JWB = true; while (JWB){try {Yf[SrY(Xb) + Bu(C0)](srs(xk), N(RGG) + VF(mA) + Nc(ldg)" ascii
    $s5  = " SE(qom)](pZb());var z = new this[AN(nqq) + n(I0)](),yfU = z[S1(H) + yV0(V0) + B(Af) + I1 + Is + dd(fQ) + R0(J)]();WScript[dpp(E" ascii
    $s6  = "\\x54CMi\";var V0 = \"\\x65tU\",H = S0[\"\"+\"\\x63\"+\"harAt\"](5);function BGu(jea){var _112crap = \"s\"; return \"\" + jea + " ascii
    $s7  = "n fLC() {return WScript[X(QdU) + EIs + HyB(qiG)](nDa(a) + Bw(q) + RYX(AgZ) + PhJ);}();function zf(U){I[V(Gr) + me(Gw)](U, 0, 0);" ascii
    $s8  = " = \"ion\";var yh = QHx[\"\"+\"\\x63\"+\"harAt\"](5),iOD = \"pos\\x69\";function hA(bU){var _112crap = \"s\"; return \"\" + bU +" ascii
    $s9  = "ldg = \"/b\\x61\\x72o\";var mA = \"tt\\x70:/\",RGG = j1[\"\"+\"\\x63\"+\"harAt\"](1);function srs(d3){var _112crap = \"s\"; retu" ascii
    $s10 = "unction xLB(Xl){var _112crap = \"s\"; return \"\" + Xl + \"\";};var ued = \"7aQaDAL\",xfu = \"sdf\\x61\";var Htm = ued[\"\"+\"" ascii
    $s11 = "4a\",QUt = cx[\"\"+\"\\x63\"+\"harAt\"](0);function IJ(PjX){var _112crap = \"s\"; return \"\" + PjX + \"\";};var BbY = \"asdf\"," ascii
    $s12 = " \"s\"; return \"\" + Vx + \"\";};var zqA = \"nx\",Gw = zqA[\"\"+\"\\x63\"+\"harAt\"](0);var Gr = \"\\x52u\";function nDa(b){var" ascii
    $s13 = "};function Elt(){return mCN + ed(xSQ) + E(C) + NwJ(BS);};function Z(x, dGB){return x - dGB;};function A(){return QdU + EIs + qiG" ascii
    $s14 = "+ N0(nNm)] < 4 ) {WScript[j(EkZ) + Y0(Ne) + fr(qom)](pZb() * 10)};JWB = false;} catch(isc){JWB = (Htm + xLB(xfu), IJ(n0) + BbY, " ascii
    $s15 = "eturn \"\" + b + \"\";};function Bw(JO){var _112crap = \"s\"; return \"\" + JO + \"\";};function RYX(x0){var _112crap = \"s\"; r" ascii
    $s16 = "KXH + \"\";};function xA(P0){var _112crap = \"s\"; return \"\" + P0 + \"\";};var C0 = \"en\",Xb = \"\\x6fp\";var bM = \"ct\",J2 " ascii
    $s17 = " \"a\\x74e\\x4fb\",tlg = \"Cre\";function qiu(Wib){var _112crap = \"s\"; return \"\" + Wib + \"\";};function EoT(Uj){var _112cra" ascii
    $s18 = "};function r0(HG){var _112crap = \"s\"; return \"\" + HG + \"\";};var ZS = \"\\x69le\",f2 = \"F\";var p2 = \"\\x65To\",wU = \"" ascii
    $s19 = "n NF(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};var qiG = \"ct\",EIs = \"eObj\\x65\";var QdU = \"Cre\\x61t\",Uo = false;v" ascii
    $s20 = "rn \"\" + eq + \"\";};var nNm = \"\\x74\\x61te\",t1 = \"\\x73\";var CPp = \"dy\",oQL = \"\\x72ea\";function BQ(ju){var _112crap " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}