rule sig_20160321_695aa8f52b942908a561fe7055ee346f {
  meta:
    description = "datamaliciousorder - file 20160321_695aa8f52b942908a561fe7055ee346f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59b54deb9798c6a44b02d043fbe385335cb105b94bf8bbf302bdea5e5c728e7d"

  strings:
    $s1  = "function zJXu(FqXm){return FqXm;};var pyJ = \"6\\x38162\";var LIEhQ = \"2183\";function ppE(C1){return C1;};function pNHT(sC){re" ascii
    $s2  = "return fIXYH;};var z = \"%ySIBA\";var CSa = \"\\x25/\";var Szsq = \"TEMP\";var zxjJ = z[\"charAt\"](0);function lFI(oZZ){return " ascii
    $s3  = "charAt\"](5);var w0 = \"\\x4f\";var sj = \"ate\";var gylhn = \"C\\x72e\";var SBtaO = function ixx() {return WScript[(function RG" ascii
    $s4  = "on bDXJ(){return YdtJ;}())]();var ziasR = SNJXd[x0(nY) + y + mU + nkc + (function n0(){return Yv;}())]();WScript[P + Jws(vFK)](A" ascii
    $s5  = "tion bEw(){return CxVQa;}()) + rGu(Lvyl); st = dUaqM(); Mndr = WScript[bo(gylhn) + W(sj) + (function Oz(){return w0;}()) + xhGx " ascii
    $s6  = "nction W0(){return Yv;}())]();WScript[(function CplRF(){return P;}()) + EzL(vFK)](AjtSw());var SNJXd = new this[dUi(a) + (functi" ascii
    $s7  = "){};}rXH = WScript[MaXT()]((function Sqhsq(){return DxfgC;}()) + AtaqG(l) + C0(VDdH) + cnxQf(k) + Ebvd(ZSOyH) + (function okBBT(" ascii
    $s8  = "PvRB + (function bT(){return MG;}()) + V0(Ysx) + T(iC);};function jlDnp(yh, jJz){return yh - jJz;};function MaXT(){return (funct" ascii
    $s9  = "Um && gnPso;};if (w()){sK = SBtaO[lFI(pOskW) + (function ipZRr(){return xcf;}()) + MRNsO(adJ) + eIHi(Yw) + (function sg(){return" ascii
    $s10 = "nction gah(){return LciCI;}()) + slou] < 4 ) {WScript[P + (function IdFO(){return vFK;}())](AjtSw() * 10)};ILf = false;} catch(e" ascii
    $s11 = "2);var l = \"ODB\";var DxfgC = \"AD\";var ymgsk = \"pG0ug\";var KfMCG = ymgsk[\"charAt\"](0);var N0 = \"\\x53le\\x65\";function " ascii
    $s12 = "X\";var PvRB = \"ML2\";var B0 = \"M\\x53X\";function kqdu(n){return n;};var u = \"DgzFvnKF\";var sP = u[\"charAt\"](5);var nTcmA" ascii
    $s13 = "on UV(p){return p;};var qNgA = \"dnrWAptyF3\";var AU = \"d\\x79\";var T1 = \"nseB\\x6f\";var zRHsa = \"o\";var bX = qNgA[\"charA" ascii
    $s14 = "= \"\\x6c\\x6c\";var tdZr = \"t.S\\x68e\";var RF = \"\\x53\\x63\\x72ip\";var cfPx = rfHRw[\"charAt\"](5);function KLoEE(vmld){re" ascii
    $s15 = "at\";var T0 = lt[\"charAt\"](1);function V0(f){return f;};function T(tgYQ){return tgYQ;};var iC = \"TTP\";var Ysx = \"MLH\";var " ascii
    $s16 = "on RSG(y1){return y1;};var fRFl = \"ke7\";var es = fRFl[\"charAt\"](1);var YS = \"F\\x69l\";var Fw = \"veT\\x6f\";var xEDhH = \"" ascii
    $s17 = "{return WtrKH;};var I = \"ceXaw\";var slou = I[\"charAt\"](1);var LciCI = \"s\\x74\\x61t\";var H = \"r\\x65\\x61dy\";function ig" ascii
    $s18 = " = nTmA[\"charAt\"](5);var CQAX = \"g\\x65\\x74M\";var mw = \"Date\";function EzL(XU){return XU;};function Jws(yqUXH){return yqU" ascii
    $s19 = " eoZEt = \"ARtupYha\";var vFK = eoZEt[\"charAt\"](4);var P = \"S\\x6ce\\x65\";function pRdJS(pg){return pg;};function x0(Ht){ret" ascii
    $s20 = "hm;}()) + (function rndm(){return V1;}()) + PswyV(Y0) + (function PNPy(){return qdFs;}())] = 0;rXH[(function AseH(){return xEDhH" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}