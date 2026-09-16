rule sig_20160321_18042743468157077abcf9ffb1a90122 {
  meta:
    description = "datamaliciousorder - file 20160321_18042743468157077abcf9ffb1a90122.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd287e847980a3a4a63c4fb53caa09ac996a29229079032e294cbd53796dab97"

  strings:
    $x1  = "function Ir(xiT){return xiT;};var B = \"68162\";var iy = \"218\\x33\";var ttk = \"Ee2AFauF6\";var WzI = \"sdf\";var jpv = \"sd" ascii
    $s2  = "x74p:\";function sZdE(zMV){return zMV;};var UyC = \"GET\";function geW(Nl){return Nl;};function T0(x0){return x0;};var TJcH = \"" ascii
    $s3  = "function NAYNa(){return n;}()) + (function Tk(){return ZoGjz;}())]();WScript[W](wV());var bAXh = new this[M + (function vRpps(){" ascii
    $s4  = "3t\";var rxp = \"\\x65Obje\";var nwhu = \"\\x43reat\";var EZ = function hNt() {return WScript[(function Xw(){return nwhu;}()) + " ascii
    $s5  = "(); JFT = WScript[nwhu + nncN(rxp) + E](D); var LTllV = true; while (LTllV){try {JFT[geW(TJcH)](sZdE(UyC), cceIj(PoT) + RAEDx + " ascii
    $s6  = "P;}()) + q(MgFHA) + vCxYi(jLfB) + (function sRZyK(){return n;}()) + rh(ZoGjz)]();WScript[VTBkp(W)](wV());var bAXh = new this[M +" ascii
    $s7  = "V\";var rLk = ziHXI[\"charAt\"](4);var PsJKa = \"tat\";var KcmB = \"\\x79s\";var n0 = \"read\";var MkP = \"en\\x64\";var fnkPi =" ascii
    $s8  = "ction J0(GOa){return GOa;};function H(zE){return zE;};var ppUR = \"MnPW\";var U = \"LHTTP\";var EIVZM = ppUR[\"charAt\"](0);var " ascii
    $s9  = " H(U);};function VdQem(A, jEeC){return A - jEeC;};function sNxT(){return hJq(nwhu) + GnTG(rxp) + E;};function wV(){return 22;};f" ascii
    $s10 = "H = false;for (var czC = 0; czC < wV() * 1; czC++){if (Tlm() != 0){G = true;IH = true;break;}}function ug() {return G && IH;};if" ascii
    $s11 = "n0 + KuJ(KcmB) + PsJKa + Rh(rLk)] < 4 ) {WScript[(function i(){return W;}())](wV() * 10)};LTllV = false;} catch(e){};}av = WScri" ascii
    $s12 = " jw(ktlr){return ktlr;};var AeJ = \"YdC4a\";var ZoGjz = \"s\";var n = AeJ[\"charAt\"](1);var jLfB = \"on\";var MgFHA = \"isec\";" ascii
    $s13 = "M0(oW){return oW;};var VcZ = \"sg\";var WE = \"s\\x63\";var fWI = \"d\\x61\";var yFVOl = VcZ[\"charAt\"](1);var m = \"3\\x68\";v" ascii
    $s14 = "r X = ttk[\"charAt\"](5);function nAQ(gXMwd){return gXMwd;};function xc(R0){return R0;};function YYpS(Fh){return Fh;};function M" ascii
    $s15 = "Zw91\";var YbBeM = T[\"charAt\"](4);var ORAnT = \"\\x72\\x69ng\";var UIyP = \"n\\x74S\\x74\";var iYTZ = \"me\";var Kj = \"\\x76i" ascii
    $s16 = "= \"\\x77\\x72i\\x74\";function clK(w){return w;};var DGtGY = \"eV\";var c1 = DGtGY[\"charAt\"](0);var xHTQS = \"typ\";var q1 = " ascii
    $s17 = "};function NJla(aZKJH){return aZKJH;};var VsQUc = \"7PiaFe\";var H1 = VsQUc[\"charAt\"](5);var Ska = \"\\x69l\";var zDs = \"veT" ascii
    $s18 = "p\";var Bx = \"le\";var W0 = kbyqe[\"charAt\"](0);function KuJ(TYFJ){return TYFJ;};function Rh(XLuc){return XLuc;};var ziHXI = " ascii
    $s19 = " \"\\x6c\";var Pc = \"\\x69\\x6c\";var jWv = \"getM\";function UGL(jcto){return jcto;};function yFe(OQ){return OQ;};var RAbQ = " ascii
    $s20 = " VeSAa = \"get\";var q0 = \"e\";var vW = \"Dat\";function VTBkp(gv){return gv;};var W = \"S\\x6ce\\x65p\";function q(Tww){return" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}