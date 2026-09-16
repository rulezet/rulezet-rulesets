rule sig_20160321_bd0e1c78808f7f76894d7dff84c102b3 {
  meta:
    description = "datamaliciousorder - file 20160321_bd0e1c78808f7f76894d7dff84c102b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99d66634cf4a599d231f9fc3c5e25b4730594ebf9af6fc7b0d4ef14a06bcc97b"

  strings:
    $s1  = "var IV = \"E2k\";var Qqll = IV[\"c\\x68arAt\"](1);var KYXT = \"6\\x3816\";var Yy = \"2\\x31\\x383\";var WdTu = \"sd\\x66\";var h" ascii
    $s2  = "n g(){return XQ;}()); v = Lq(); tDJz = WScript[(function UpQdh(){return R;}()) + (function PU(){return cOC;}()) + VbMP + JaeIb +" ascii
    $s3  = "turn WScript[DGOoW(R) + cOC + (function u(){return VbMP;}()) + JaeIb + DTguu(YeLp)]((function OLVKl(){return QY;}()) + T0(sKMn) " ascii
    $s4  = "+ (function Ss(){return URQT;}()) + JN]();WScript[(function Eepb(){return I;}()) + U](thcqr());var WzkWm = new this[(function Jk" ascii
    $s5  = "{return JN;}())]();WScript[HYYQo(I) + (function h(){return U;}())](thcqr());var WzkWm = new this[(function pzbBX(){return pVXQ;}" ascii
    $s6  = "cq, 0, 0);};function Lq(){return e(L0) + Cs + zaIsc;};function sshV(zS, xkl){return zS - xkl;};function z(){return (function kn(" ascii
    $s7  = "A < thcqr() * 1; WA++){if (cBP() != 0){OSF = true;xJPlu = true;break;}}function T() {return OSF && xJPlu;};if (T()){wNab = p[ggD" ascii
    $s8  = "x65\";var SVchd = \"Cre\\x61t\";function e(rnuS){return rnuS;};var zaIsc = \"HTTP\";var Cs = \"\\x32.XML\";var L0 = \"MS\\x58\\x" ascii
    $s9  = "{WScript[(function G(){return I;}()) + U](thcqr() * 10)};ZG = false;} catch(e){};}POGUd = WScript[z()](X(mSHn) + PZ + (function " ascii
    $s10 = "= Ezy[\"c\\x68arAt\"](2);function DGOoW(iN){return iN;};function DTguu(MGj){return MGj;};function b(IQnXa){return IQnXa;};functi" ascii
    $s11 = "n GfKbv(GAEx){return GAEx;};var WhPY = \"Gnf\";var Nu = WhPY[\"c\\x68arAt\"](1);var aO = \"\\x52u\";function T0(gDZ){return gDZ;" ascii
    $s12 = " \"\\x73iti\";var pZ = \"po\";function i(mba){return mba;};function Oz(ucD){return ucD;};var wIX = \"FLHy\";var jJ = wIX[\"c\\x6" ascii
    $s13 = " \"ZO\";var K = u0[\"c\\x68arAt\"](1);var diL = \"\\x564GwD\";var DQLzI = mNBF[\"c\\x68arAt\"](4);function l(M){return M;};funct" ascii
    $s14 = "return B0;};var k = \"T3TM5\";var LHHXH = \"P\\x25/\";var jlL = \"EM\";var frD = k[\"c\\x68arAt\"](2);var ja = \"%\";function gg" ascii
    $s15 = "ar UOJv = \"get\\x4d\";var oXr = \"t\\x65\";var mNPEn = \"a\";var v0 = \"D\";function HYYQo(wfjz){return wfjz;};var U = \"ep\";v" ascii
    $s16 = ") + oG + WS + (function Q(){return NXld;}()) + BX(Bry) + Kbgyl(xkYI) + VNvmw + M0 + Env + w0 + (function bW(){return pzf;}()), f" ascii
    $s17 = "WzkWm = new this[NZWvX(pVXQ) + mfT(VyT)]();var fP = WzkWm[(function CBvA(){return bY;}()) + (function DHaeW(){return kpjMM;}()) " ascii
    $s18 = "){return R;}()) + b(cOC) + (function lpl(){return VbMP;}()) + L(JaeIb) + YeLp;};function thcqr(){return 22;};function cBP(){var " ascii
    $s19 = "Dxz;}()) + (function dCs(){return Ar;}())] = 0;POGUd[Z0(v1) + g0(uc) + q0 + fUQHA](wNab, 2 );POGUd[e0(omvS) + c0]();PNnpL(wNab);" ascii
    $s20 = " + OSF ? hiM + WdTu : Yy + (function i0(){return KYXT;}()) + Qqll;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}