rule sig_20160321_1b1ab433e6b7407c6efed1b86dbcdd3d {
  meta:
    description = "datamaliciousorder - file 20160321_1b1ab433e6b7407c6efed1b86dbcdd3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9792e8e6b368ebab4f1dcf79652143b6b87208441b520a57c55077e44bdf52d6"

  strings:
    $s1  = "var lbQkP = \"6iG22ycJr\";var EC = lbQkP[\"\\x63\\x68ar\\x41\\x74\"](4);var PTO = \"36816\";var mX = \"218\";var Ny = \"\\x73\\x" ascii
    $s2  = "tion lqcg(){return EXmx;}()) + cIB(YX)]();WScript[(function cULKU(){return Nzm;}()) + EGxmj(IdBV) + (function kyP(){return QapYC" ascii
    $s3  = " an(); kdaR = WScript[(function Otmo(){return TXeiq;}()) + Bcj(C) + (function n0(){return Qblw;}()) + (function xfrz(){return na" ascii
    $s4  = "x74\\x65Ob\";var TXeiq = \"Cre\\x61\";var znyzU = function bbSmr() {return WScript[TXeiq + C + (function n(){return Qblw;}()) + " ascii
    $s5  = "eturn Lfg;}()) + HWQ(EXmx) + e(YX)]();WScript[Lx(Nzm) + IdBV + lS(QapYC)](wc());var HcS = new this[cIIx + X(KvBMw) + (function B" ascii
    $s6  = " F0(Xf), false);kdaR[X1 + mF + qMwZE(EaOsu)]();while (kdaR[WU(gwr) + QUAHe(iFm) + FGF(wzV)] < 4 ) {WScript[Nzm + IdBV + AcMu(Qap" ascii
    $s7  = "){return nxZ;}())](Upbq + (function Ey(){return Gc;}()) + Spy(tYBoE)) + AsR(XwhQ) + (function ut(){return DnnqI;}()) + p0; ANA =" ascii
    $s8  = "return wuE;}());};function q(Zaf, YVtj){return Zaf - YVtj;};function BRv(){return TXeiq + (function pogGI(){return C;}()) + (fun" ascii
    $s9  = "r nP = 0; nP < wc() * 1; nP++){if (Opd() != 0){a = true;t = true;break;}}function MEDat() {return a && t;};if (MEDat()){snUZQ = " ascii
    $s10 = "YC)](wc() * 10)};gx = false;} catch(e){};}yYL = WScript[BRv()](dxLL + (function zS(){return y0;}()) + (function LAUTs(){return u" ascii
    $s11 = "nnqI = \"PX\\x67\\x73L\";var XwhQ = \"\\x37L3\";function Spy(X0){return X0;};var xAVL = \"Et0W\";var tYBoE = \"\\x4dP\\x25/\";va" ascii
    $s12 = "))](snUZQ, 2 );yYL[K1]();rHm(snUZQ);ML = \"\" + (function AuyLy(){return I2;}()) + (function iM(){return M0;}()) + (function HOF" ascii
    $s13 = " eepb(){return LA;}()) + (function IqWf(){return w0;}()) + (function feVIC(){return di;}()) + Gb(jud) + (function Yh(){return oM" ascii
    $s14 = ")) + (function qhO(){return XuNL;}()) + (function JQyoJ(){return hk;}()) + YcRk(ux) + (function MY(){return wAReC;}()) + vAXOZ +" ascii
    $s15 = "kJsT(){return trGid;}())]();var DSJo = HcS[oSS(Sjm) + (function I0(){return K;}()) + Lfg + EXmx + (function DAP(){return YX;}())" ascii
    $s16 = "znyzU[yLR(pJ) + (function DAQ(){return clMU;}()) + K0 + ltejI + (function fn(){return VPyvg;}()) + wc0 + p + M + (function DylJ(" ascii
    $s17 = "ction Rwa(){return Qblw;}()) + (function ybMA(){return nasQi;}());};function wc(){return 22;};function Opd(){var HcS = new this[" ascii
    $s18 = ";}()) + iMtaT(L)]);yYL[NiLn(B1) + y1(Mvs)] = 0;yYL[(function IF(){return QGKAT;}()) + wIjvc(SGvk) + (function CG(){return vtQ;}(" ascii
    $s19 = "(){return d0;}()) + Xopsk(g) + ubY(f) + a ? (function gGopv(){return UJYr;}()) + Ny : mX + (function dFDC(){return PTO;}()) + (f" ascii
    $s20 = "){return uhRe;}()) + JvFBq(S) + qfm(txviH) + (function ytnAC(){return KqB;}()) + nLLj + ZSQ(a0) + LaRgG + hPep + (function LQHHw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}