rule sig_20160321_48658be85051b574247ad71af151eca7 {
  meta:
    description = "datamaliciousorder - file 20160321_48658be85051b574247ad71af151eca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc4ae6a94b333b4ac192528a74dbdef3293910622e93fee6900fcdc2ce24340e"

  strings:
    $s1  = "function aLtg(O){return O;};var p = \"8\\x3162\";var CWuU = \"21836\";function qv(k1){return k1;};function eCK(Rc){return Rc;};f" ascii
    $s2  = "Script[GRv + mm + (function naB(){return yt;}()) + (function zzs(){return C;}())](AQqjE(R) + bLmI(YrIkw) + Giolr + (function xSM" ascii
    $s3  = "j(rf) + (function ejGns(){return AECs;}()) + wojcl(gfOaI); g = B(); LVGS = WScript[(function xPQcX(){return GRv;}()) + dhz(mm) +" ascii
    $s4  = "turn tBvyb;}())]();var NbIq = Jah[N(mrN) + FzS + Pz(B0) + (function eZVWp(){return oLqs;}())]();WScript[ilEAU + T1(jz)](G());var" ascii
    $s5  = "(){return FzS;}()) + FK(B0) + (function KF(){return oLqs;}())]();WScript[Gp(ilEAU) + e(jz)](G());var Jah = new this[(function Q(" ascii
    $s6  = "nction qz(){return yt;}()) + C;};function G(){return 22;};function Dq(){var Jah = new this[Get(Mw) + a(o) + (function DsZKq(){re" ascii
    $s7  = ")) + XGhog(fuCWi) + KdlY(T) + vaQ(EAIs);};function EXV(va, voeYu){return va - voeYu;};function wwZ(){return GRv + PjIj(mm) + (fu" ascii
    $s8  = "for (var oQYvG = 0; oQYvG < G() * 1; oQYvG++){if (Dq() != 0){gMZO = true;MC = true;break;}}function IrMl() {return gMZO && MC;};" ascii
    $s9  = "< 4 ) {WScript[(function D0(){return ilEAU;}()) + TDw(jz)](G() * 10)};xZxF = false;} catch(e){};}Rpsgb = WScript[wwZ()](jk + J0 " ascii
    $s10 = "GET\";function vlAqZ(A){return A;};var cgwK = \"en\";var Xwjr = \"\\x6f\\x70\";var n = \"k0sstrahs\";var ZlOFI = n[\"cha\\x72\\x" ascii
    $s11 = "r B0 = \"\\x63o\\x6e\\x64\";var FzS = \"ll\\x69\\x73e\";var mrN = \"ge\\x74\\x4di\";function Get(DFvo){return DFvo;};function a(" ascii
    $s12 = "on LKfc(){return Uf;}())](LVGS[(function bFbwR(){return d0;}()) + WrB(qsl) + (function ZrZ(){return mRJP;}()) + Fz(G0) + (functi" ascii
    $s13 = " qZfYl(ZszX) + UY + R0(rQcx) + Q0(TtNBO) + (function isy(){return JPXyw;}()) + Vs(Ji) + PAM(vv) + cLW(P) + (function OIbf(){retu" ascii
    $s14 = "+ MZ + (function D1(){return HsdF;}()));Rpsgb[(Xwjr + vlAqZ(cgwK))]();Rpsgb[iIcPP + wxQ(A0)] = 1;Rpsgb[F0 + aaTWe(BwJ) + (functi" ascii
    $s15 = " Jah = new this[Mw + Zxctf(o) + (function df(){return tBvyb;}())]();var cnfRb = Jah[(function VV(){return mrN;}()) + (function H" ascii
    $s16 = "if (IrMl()){gm = Pax[(function ABbyd(){return BpwP;}()) + XXnhw + WvY(aqRdF) + (function Mu(){return t0;}()) + ruMp(dI) + (funct" ascii
    $s17 = "Y(){return tM;}()));}();function l(NavPc){Pax[MDdAf(mg)](NavPc, 0, 0);};function B(){return YpT + (function eTQv(){return pHI;}(" ascii
    $s18 = "ion Pfy(){return wiUz;}()) + b(W) + wCcdN](JMP(nNJK) + (function fT(){return AebRO;}())) + ZlUU(WyiB) + dECJ + Iqsno + Cc + slWc" ascii
    $s19 = " t(yt) + (function vrBa(){return C;}())](g); var xZxF = true; while (xZxF){try {LVGS[Xwjr + (function c(){return cgwK;}())](eC, " ascii
    $s20 = "){return Mw;}()) + Epekp(o) + (function xli(){return tBvyb;}())]();var NunQl = Jah[stN(mrN) + FzS + UtNe(B0) + oLqs]();var ULAH " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}