rule sig_20160321_6992ecd137c43f8a18a74d8b32064069 {
  meta:
    description = "datamaliciousorder - file 20160321_6992ecd137c43f8a18a74d8b32064069.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f7b103e925fb480ddac820dc094e658b3cb0fbcb00de20792ae6e46d1b8176b"

  strings:
    $s1  = "function BGjiI(hfCZ){return hfCZ;};var hPj = \"6q838M\";var lA = \"M32bPpE9\";var d0 = lA[\"char\\x41\\x74\"](2);var hNdt = hPj[" ascii
    $s2  = "tion PAvpJ(){return fOk;}())]();WScript[gv + (function gnz(){return Py;}())](tD());var UzkZ = new this[RDB]();var LPoXz = UzkZ[j" ascii
    $s3  = " false);Cyp[vu]();while (Cyp[(function B(){return Xr;}()) + vtSo(XfC) + VPm(Cm) + tOLl] < 4 ) {WScript[ke(gv) + (function zGfP()" ascii
    $s4  = " + lbPa(Pi)) + Nk + Me(hvCx) + (function kQxO(){return qMC;}()) + YUy(NGAW) + S1; BOXRK = YVI(); Cyp = WScript[(function L(){ret" ascii
    $s5  = "Llff) + (function M0(){return JVMdz;}()) + (function mXDm(){return fOk;}())]();WScript[gv + vj(Py)](tD());var UzkZ = new this[RD" ascii
    $s6  = "on YVI(){return c + (function qXTC(){return HYb;}()) + (function bH(){return FF;}()) + F;};function X(UAvOQ, lJp){return UAvOQ -" ascii
    $s7  = "YA = false;for (var HV = 0; HV < tD() * 1; HV++){if (AS() != 0){XBdM = true;YA = true;break;}}function zE() {return XBdM && YA;}" ascii
    $s8  = "eturn Ht;};var bKnu = \"ect\";var ixUfX = \"eO\\x62\\x6a\";var I = \"C\\x72eat\";var Qyp = function pgRc() {return WScript[(func" ascii
    $s9  = "{return Py;}())](tD() * 10)};E = false;} catch(e){};}g = WScript[s()]((function W(){return AtY;}()) + (function LWRn(){return cz" ascii
    $s10 = "return cccM;};var RDB = \"Date\";var HHZi = \"\\x74\";var uNhj = \"\\x63\";var tTU = \"b\\x6ae\";var s0 = \"\\x74eO\";var dlL = " ascii
    $s11 = "}()) + M + (function FQygl(){return Gm;}()));}();function sIXQ(J){Qyp[(function f(){return r;}()) + UqyRt(YK)](J, 0, 0);};functi" ascii
    $s12 = "(){return CP;}()) + (function ql(){return KVAm;}()) + vkvdj]((function fm(){return qAuQv;}()) + (function VYEg(){return FMa;}())" ascii
    $s13 = " 0;g[ynNVq + XY(Gl) + (function djf(){return rVQ;}()) + (function CJhL(){return JKC;}()) + (function wAxoB(){return lYmnI;}()) +" ascii
    $s14 = "())](Cyp[Lwxlq(Niof) + (function NFZ(){return qXpm;}()) + DbFsy(GBaZ)]);g[tKSdH(j1) + (function VK(){return N;}()) + epkk(a0)] =" ascii
    $s15 = "n gKts(){return j0;}()) + (function Kdfh(){return t;}()) + eSWR(bzqZe) + J1(vxQL) + Fv(zmY) + OjDX(WFE) + i(zOoXI) + ENlZO + E0," ascii
    $s16 = " (function RSHW(){return VB;}())](esWD, 2 );g[(function R(){return Wu;}()) + (function O(){return EncJJ;}())]();sIXQ(esWD);qBZW " ascii
    $s17 = "EPmF + (function S(){return Xmkb;}()) + qEB(jaB) + (function DcTe(){return SLlff;}()) + (function jjXGk(){return JVMdz;}()) + fO" ascii
    $s18 = "{return I;}()) + (function NEjHE(){return ixUfX;}()) + bKnu]((function fs(){return d;}()) + cm(Q) + (function qB(){return PpfLV;" ascii
    $s19 = " lJp;};function s(){return (function IK(){return I;}()) + EgIM(ixUfX) + bKnu;};function tD(){return 22;};function AS(){var UzkZ " ascii
    $s20 = "urn I;}()) + IMe(ixUfX) + pNs(bKnu)](BOXRK); var E = true; while (E){try {Cyp[(function rMvp(){return Doqn;}())](JiYhW, (functio" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}