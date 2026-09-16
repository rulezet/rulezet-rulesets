rule sig_20160321_6a51b238d9c490a2609a92bce74e1ef6 {
  meta:
    description = "datamaliciousorder - file 20160321_6a51b238d9c490a2609a92bce74e1ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c33d6dc6e00ff24ffaba4346085ec5eb927d02d3556c258792e31864815e1479"

  strings:
    $s1  = "function qK(NMn){return NMn;};var dN = \"UM4u6\";var fZjl = \"O8WFo\";var ZvpyH = \"gq1\";var gQeI = \"\\x362\";var nu = ZvpyH[" ascii
    $s2  = "Y(); npkm = WScript[wNN(FSZcp) + Ff(X) + ZFS + vntxJ](O); var kYr = true; while (kYr){try {npkm[(function PKzKj(){return FMaE;}(" ascii
    $s3  = "QR(){return Q;}()), false);npkm[r(kb) + YtTo]();while (npkm[(function Cbaw(){return FifPB;}()) + uvha + WIaY(K)] < 4 ) {WScript[" ascii
    $s4  = "r FSZcp = \"\\x43r\\x65a\";var rs = function R() {return WScript[IvQLK(FSZcp) + ds(X) + (function NpsC(){return ZFS;}()) + (func" ascii
    $s5  = "rn v;}()) + yvoBv(ghH) + eRsM(s)]();WScript[KxyFw(eWtm) + XPGc](Ev());var NPlm = new this[(function rpx(){return Pyw;}()) + WAT " ascii
    $s6  = "){return Fc;}()) + v + FGsJ(ghH) + Cz(s)]();WScript[eWtm + (function zlmCp(){return XPGc;}())](Ev());var NPlm = new this[Cf(Pyw)" ascii
    $s7  = "on Dc(){return r1;}()) + (function P4(){return v0;}()) + (function dgrT(){return XGrG;}()) + nPqzW(eyEN) + GeE + thx(TTPl) + n(G" ascii
    $s8  = "+ QqW(YwBy);};function BuDn(eyLIM, CxYvo){return eyLIM - CxYvo;};function bHky(){return FSZcp + (function j(){return X;}()) + (f" ascii
    $s9  = "NBh(eWtm) + jz(XPGc)](Ev() * 10)};kYr = false;} catch(e){};}yhu = WScript[bHky()](HyQoR + N + X0(cn));yhu[(FMaE)]();yhu[(functio" ascii
    $s10 = "(function UxCoC(){return CoGw;}()) + LSAT + (function U(){return m;}()) + qK(nu) + (function iPI(){return gQeI;}());}" fullword ascii
    $s11 = "a7\";var TTPl = \"sd\";var GeE = \"h\\x67\";var eyEN = QzO[\"charA\\x74\"](2);var XGrG = \"\\x73\\x64fau\";var v0 = \"kj\\x61o\"" ascii
    $s12 = " + ENgNo(WAT) + bGEh(P)]();var MqUBk = NPlm[(function o1(){return H;}()) + (function KbCm(){return sLwZs;}()) + qDmlA(Slp) + QDP" ascii
    $s13 = "r F = NPlm[bE(H) + QxC(sLwZs) + Slp + (function Gkcyz(){return QDP;}()) + (function rrnp(){return Fc;}()) + (function Dzn(){retu" ascii
    $s14 = "XkB) + YBF + QdvXP + cQHv + qhOh(QxZzD) + aWnaq ? (function UPFr(){return PK;}()) + (function tCt(){return zyQAR;}()) + LPKHd : " ascii
    $s15 = "unction sB(){return ZFS;}()) + o(vntxJ);};function Ev(){return 22;};function TNc(){var NPlm = new this[Pyw + WAT + pxZq(P)]();va" ascii
    $s16 = " 0;yhu[bM(AZ) + TDPJS(r0) + WeFH](hELW, 2 );yhu[dbj(pSIPY) + (function PZwvw(){return F3;}())]();zRxzM(hELW);LXGa = \"\" + (func" ascii
    $s17 = " Qm(){return vntxJ;}())](DQ + i + (function htv(){return GqtbP;}()) + yYESx);}();function zRxzM(niEF){rs[(function oZq(){return " ascii
    $s18 = " + bHbMS + (function VsQ(){return bYh;}()) + BZviD + (function hWUi(){return H0;}()) + px(Kokgz) + (function vvAbO(){return Hev;" ascii
    $s19 = "))]((function DHAD(){return P1;}()) + (function aqQC(){return gFsv;}()), (function RXdCh(){return WJ;}()) + (function w(){return" ascii
    $s20 = "FPk;}())](niEF, 0, 0);};function tOY(){return (function kJ(){return qaCtq;}()) + (function DQ0(){return R0;}()) + Cxe + o0(CcV) " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}