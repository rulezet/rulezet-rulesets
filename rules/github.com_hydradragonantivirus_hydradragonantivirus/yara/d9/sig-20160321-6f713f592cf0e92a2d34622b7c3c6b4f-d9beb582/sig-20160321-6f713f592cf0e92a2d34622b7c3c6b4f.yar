rule sig_20160321_6f713f592cf0e92a2d34622b7c3c6b4f {
  meta:
    description = "datamaliciousorder - file 20160321_6f713f592cf0e92a2d34622b7c3c6b4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "541b793a536775e61854ee261e4e16d091767da8a3bcb81925d332a73053613f"

  strings:
    $s1  = "function AuIfz(FFMVE){return FFMVE;};var uBvPQ = \"N2S6m73\";var YofIW = uBvPQ[\"cha\\x72At\"](1);var soVZa = \"6\";var vftV = " ascii
    $s2  = "}()) + (function Vd(){return TX;}()) + gcXvP(wf) + SSia(fB) + xYE]();WScript[(function uVqCV(){return K0;}())](XNIve());var oXu " ascii
    $s3  = ");while (IZSz[lITC + zDg(qaiV) + (function Fi(){return O0;}()) + aS(i) + (function l(){return frGR;}())] < 4 ) {WScript[(functio" ascii
    $s4  = " xgPL = \"o.com\";var Ohl = \"mc\";var xEvg = \"rfa\";var nZCQJ = \"://za\";var FWLr = \"ht\\x74\\x70\";var XTw = \"GE\\x54\";fu" ascii
    $s5  = "){return yyt;}()) + Lms; BOWvJ = coI(); IZSz = WScript[hy + (function ZNw(){return sHgm;}()) + (function Asnz(){return Ym;}()) +" ascii
    $s6  = " N0(){return TX;}()) + wf + fB + (function mj(){return xYE;}())]();WScript[(function I(){return K0;}())](XNIve());var oXu = new " ascii
    $s7  = "{return K;}()) + Hakv(Ir) + MKqdM(gIGtd);};function LX(q, xDl){return q - xDl;};function Y(){return KqIW(hy) + m(sHgm) + (functi" ascii
    $s8  = " aNK++){if (KFw() != 0){a = true;PiNx = true;break;}}function qIX() {return a && PiNx;};if (qIX()){qPO = KPC[YZqTY(OO) + Ym0(JPa" ascii
    $s9  = "x74\";var qn = \"O\\x62j\";var E = \"e\";var Ym = \"at\";var sHgm = \"e\";var hy = \"\\x43\\x72\";var KPC = function j() {return" ascii
    $s10 = "n UBy(){return K0;}())](XNIve() * 10)};lWS = false;} catch(e){};}F = WScript[Y()](m0(pL) + NnQrz(dP) + s1(d) + xswq(gtUt) + (fun" ascii
    $s11 = "))]();J(qPO);geUZw = \"\" + (function UDfO(){return W;}()) + (function k(){return AMq;}()) + (function aO(){return lZch;}()) + a" ascii
    $s12 = " E + ol(qn) + U](BOWvJ); var lWS = true; while (lWS){try {IZSz[eJX](XTw, FWLr + vIJbi(nZCQJ) + (function QSuD(){return xEvg;}())" ascii
    $s13 = "D(vKPd) + jxBkr(OvZ) + (function wNqo(){return kdNKd;}()) + iJN(zHUF) + sAW(kn) + (function lyf(){return hjK;}()) + (function vS" ascii
    $s14 = "= new this[(function HP(){return xryaz;}()) + j0 + HrOwQ]();var mkUKO = oXu[(function F0(){return xmZ;}()) + (function QiCJ(){re" ascii
    $s15 = "on pE(){return TqM;}()) + Wno(nN) + (function gEV(){return JFYM;}()) + KA] = 0;F[mYUj(Ook) + (function tJ(){return BPu;}()) + Cp" ascii
    $s16 = "h) + N3(NVtSw)] = 1;F[pfY(b)](IZSz[b0(HVhn) + (function GJR(){return Xut;}()) + (function MU(){return tEPb;}()) + g0]);F[(functi" ascii
    $s17 = "ction y0(){return CdSKU;}()) + (function jW(){return aLBSA;}()));F[(Vm(eJX))]();F[(function kbJ(){return bsMQH;}()) + AZUFD(iEQw" ascii
    $s18 = "hy) + (function hYU(){return sHgm;}()) + Ym + Iss(E) + (function z(){return qn;}()) + (function Hhqjz(){return U;}())](Uq(ve) + " ascii
    $s19 = "Uu(MCU) + (function YpXyT(){return KyJ;}()) + (function cBArh(){return GOdtz;}()));}();function J(Gdtg){KPC[(function nR(){retur" ascii
    $s20 = "z(UVh) + (function s3(){return pqCof;}())](qPO, 2 );F[QlQRf(ZRhFK) + (function WyO(){return r;}()) + (function BD(){return Yw;}(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}