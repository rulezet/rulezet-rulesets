rule sig_20160321_8f4e0d97b73de6a51c5b72b9014b9b0d {
  meta:
    description = "datamaliciousorder - file 20160321_8f4e0d97b73de6a51c5b72b9014b9b0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58fd86fb5d36b415439f0e1f84beaa5b45f2558492224554463227d59e58d02e"

  strings:
    $s1  = "var zZEa = \"\\x362\";var KjNk = \"\\x383\\x3681\";var FX = \"21\";function ftcv(nJ){return nJ;};var nUZw = \"iIffRI\";var fO = " ascii
    $s2  = " + (function QzrL(){return klf;}()) + qOQS(afzlg) + NmkwB(G0)]();WScript[MF + (function AKf(){return NEI;}()) + NjN(TP)](wJN());" ascii
    $s3  = "n WScript[QnW(bzS) + (function EG(){return Ga;}()) + uJMY(nych) + (function I(){return TDuko;}()) + UXdd(BCLz)](YiHY(CL) + (func" ascii
    $s4  = ") + (function PYMd(){return G0;}())]();WScript[(function deyd(){return MF;}()) + (function Jb(){return NEI;}()) + TP](wJN());var" ascii
    $s5  = "ion A1(){return pMOu;}()) + puzH(DTAS) + bxeJi] < 4 ) {WScript[BvOd(MF) + NEI + (function T(){return TP;}())](wJN() * 10)};S = f" ascii
    $s6  = ") + RFb; Hm = bGM(); pCh = WScript[(function vtupQ(){return bzS;}()) + (function oVoV(){return Ga;}()) + P(nych) + (function Ejh" ascii
    $s7  = "n bGM(){return Jn + oekTz + fybo(iPiM) + ue + mX(ng) + AEwq(jMiq) + JCD(P0);};function g(AVhEd, Vyd){return AVhEd - Vyd;};functi" ascii
    $s8  = "ak;}}function G() {return Vacy && rL;};if (G()){iSnWG = y[bKt(B) + mNxn(m0) + (function xQ(){return JYJ;}()) + NX(dzZp) + Ivc(MX" ascii
    $s9  = "alse;} catch(e){};}Aq = WScript[rDjv()](aP + A2 + (function Z0(){return q;}()) + a0 + rP + bfg(zlrY) + F1(B0));Aq[((function Xrm" ascii
    $s10 = "r klf = \"ise\";var LWtDk = \"\\x6cl\";var Mdqwx = \"get\\x4d\\x69\";function z(iai){return iai;};function moSk(ZRuuN){return ZR" ascii
    $s11 = " g(HWNz, J);}var Vacy = false;var rL = false;for (var xGb = 0; xGb < wJN() * 1; xGb++){if (uID() != 0){Vacy = true;rL = true;bre" ascii
    $s12 = "(){return TDuko;}()) + (function jU(){return BCLz;}())](Hm); var S = true; while (S){try {pCh[J0(qq) + XA(Cnpq)](vVPSw + KuX(aCd" ascii
    $s13 = "zdg;}()) + qhkY + (function cpcn(){return JYUi;}()) + (function M(){return PCiZ;}()) + (function k1(){return g0;}()) + (function" ascii
    $s14 = "ion sy(){return CJ;}()) + icsSn(ftGR)) + (function fJlD(){return XWqnr;}()) + f0(NXF) + (function W(){return H0;}()) + njh(hsrxL" ascii
    $s15 = "tion dBy(){return zB;}()) + mxgx(DFRTs) + ZThM(EVh));}();function XURim(U0){y[(function nU(){return gq;}())](U0, 0, 0);};functio" ascii
    $s16 = "no(){return qq;}()) + Cnpq)]();Aq[I0] = 1;Aq[(function aqPd(){return Cgv;}()) + (function AkREi(){return gZz;}()) + GmmQH](pCh[b" ascii
    $s17 = ") + (function ALqS(){return DdJMq;}())] = 0;Aq[wrCtE + Am + bFZr(SxD)](iSnWG, 2 );Aq[(function fPwPT(){return BL;}()) + F2(PXzTs" ascii
    $s18 = " Z(){return QNzCy;}()) + rM(e) + (function iEAf(){return dGpvv;}()) + (function l(){return dJmH;}()) + (function sX(){return r0;" ascii
    $s19 = "var bU = new this[moSk(luWw) + dJhLY(lfa) + AH]();var U = bU[Mdqwx + bymGL(LWtDk) + af(klf) + (function RbnYN(){return afzlg;}()" ascii
    $s20 = "function yEYF(){return SFn;}()) + URP(GK) + (function CT(){return GyFY;}()) + Vacy ? jJK + ftcv(Ri) + (function WgDHU(){return f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}