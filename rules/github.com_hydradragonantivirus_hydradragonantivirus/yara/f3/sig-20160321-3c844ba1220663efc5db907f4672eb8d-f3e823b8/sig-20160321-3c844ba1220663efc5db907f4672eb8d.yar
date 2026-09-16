rule sig_20160321_3c844ba1220663efc5db907f4672eb8d {
  meta:
    description = "datamaliciousorder - file 20160321_3c844ba1220663efc5db907f4672eb8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed7f2be59e8e552f1364313ba8f4973bdd7287ba715baf5a0962d9164d269f35"

  strings:
    $s1  = "function AAl(vK){return vK;};var Nwt = \"86R2\";var HlUeB = \"81\\x36\\x32\";var ng = Nwt[\"char\\x41t\"](1);var meLsy = \"\\x32" ascii
    $s2  = "();while (Zlkt[Nzx + KKWLY + zt(uj)] < 4 ) {WScript[(function Zb(){return aDqJI;}()) + (function GLWp(){return mH;}())](Qr() * 1" ascii
    $s3  = " w[sPlDz(TZeD) + (function EWL(){return MH;}()) + (function WzE(){return whokh;}()) + Oanvv(Vwy) + phb]();WScript[(function XItd" ascii
    $s4  = "hb;}())]();WScript[hN(aDqJI) + (function ZuJ(){return mH;}())](Qr());var w = new this[(function Uuf(){return r;}())]();var Twl =" ascii
    $s5  = " OC(){return QD;}()) + (function JLeXu(){return gqBK;}()); y = yXiNB(); Zlkt = WScript[(function Min(){return gPdF;}()) + (funct" ascii
    $s6  = "ar u = function QJNi() {return WScript[gPdF + (function gOoPe(){return FCTp;}()) + p(FmK) + uCG](pJ(Y) + qgo + (function X(){ret" ascii
    $s7  = "V(){return i0;}());};function Fvh(Q, uJC){return Q - uJC;};function K(){return gPdF + FCTp + wwHc(FmK) + LIXM(uCG);};function Qr" ascii
    $s8  = "nction koKVi() {return FYFzQ && unsYJ;};if (koKVi()){I = u[(function UpbWC(){return ED;}()) + q0 + cjiRY + c1(BKm) + MD(Mn) + R0" ascii
    $s9  = "0)};EgTLp = false;} catch(e){};}xQ = WScript[K()]((function S(){return eIaNh;}()) + qGAk(JHlb) + KL(NpYYA) + SdlC(G1) + fghQa(Za" ascii
    $s10 = "return Ae;};var IHThb = \"Shell\";var K0 = \"p\\x74\\x2e\";var qgo = \"\\x53cri\";var Y = \"W\";function p(A0){return A0;};funct" ascii
    $s11 = "Y = uuOXb[\"char\\x41t\"](3);function jCnY(psY){return psY;};var K1 = \"GET\";function QEXt(UZ){return UZ;};function YFdTf(FRFEA" ascii
    $s12 = "o(){return aDqJI;}()) + (function ysL(){return mH;}())](Qr());var w = new this[r]();var WcN = w[z(TZeD) + L(MH) + whokh + (funct" ascii
    $s13 = "()) + KUSi(XwJ) + (function TM(){return SQ;}()) + (function ScefE(){return G0;}()), false);Zlkt[(function vIaR(){return qj;}())]" ascii
    $s14 = "ion G(){return Vwy;}()) + phb]();var xltKb = \"lnc\";xltKb = Fvh(Twl, vvE);var Hx = \"BF\";Hx = Fvh(WcN, Twl);return Fvh(xltKb, " ascii
    $s15 = " );xQ[bECHn(YS)]();nhe(I);xltKb = \"\" + D0(Gd) + (function Szga(){return tEg;}()) + (function PbV(){return s;}()) + ufE + nJKq " ascii
    $s16 = "urn K0;}()) + ac(IHThb));}();function nhe(i){u[d](i, 0, 0);};function yXiNB(){return yPAoR(EMcKQ) + iEkk(R) + m(jw) + (function " ascii
    $s17 = "(){return 22;};function A(){var w = new this[r]();var vvE = w[c0(TZeD) + GEmU(MH) + MXn(whokh) + Vwy + (function UDWj(){return p" ascii
    $s18 = ")) + (function qmA(){return cpi;}()) + ub(tGUyR) + na(LPeGW) + yxLT + QaAwJ + IpAbN(Ku) + qeDgk(vq) + (function D(){return pms;}" ascii
    $s19 = "(function lmJ(){return gw;}()) + vf + Lhd(DiN) + TqL(jcSh) + (function a(){return KSH;}()) + rCX(SnOEd) + iGxa + FYFzQ ? (functi" ascii
    $s20 = "on ATl(){return B;}()) + mtHH + K2(c4) : (function pB(){return meLsy;}()) + AAl(ng) + (function fBw(){return HlUeB;}());}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}