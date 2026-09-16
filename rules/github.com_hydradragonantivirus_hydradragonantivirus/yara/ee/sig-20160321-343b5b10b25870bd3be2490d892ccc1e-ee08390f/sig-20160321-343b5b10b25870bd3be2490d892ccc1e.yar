rule sig_20160321_343b5b10b25870bd3be2490d892ccc1e {
  meta:
    description = "datamaliciousorder - file 20160321_343b5b10b25870bd3be2490d892ccc1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "280aadac28b6be3dfe93eb5d86cc5ad4ae289567d7b0b1b062d1b49efd2f8c8e"

  strings:
    $s1  = " = WScript[Wqqzm()](OQQN(mEhG) + rykrC(AJ) + RO(U0));dq[(Lkg + (function NoF(){return R;}()))]();dq[WqLM + (function d2(){return" ascii
    $s2  = " Yh + LPUau(Foi) + SLoi(cmO) + (function YF(){return nuid;}()); Iouu = Bs(); ifEXW = WScript[zY + DPnQO(NV) + (function rdBK(){r" ascii
    $s3  = "c\";var JqrUa = \"teObj\";var NV = \"rea\";var zY = PVqHm[\"\\x63harA\\x74\"](3);var ubW = function vo() {return WScript[zY + (f" ascii
    $s4  = "function eBAdR(){return g;}()) + (function Gnn(){return I1;}()) + Uxe(gL)]();WScript[(function ZTJ(){return vc;}()) + o0(z)](XPl" ascii
    $s5  = "function Ejf(m0){return m0;};function i0(BiiG){return BiiG;};function Dvwa(Ag){return Ag;};var HferT = \"2\";var Qqvf = \"6\";va" ascii
    $s6  = "());var i = new this[RJ + TpVXM]();var j = i[p0(u) + (function VD(){return g;}()) + pCO(I1) + sfPoh(gL)]();WScript[vc + t0(z)](X" ascii
    $s7  = "on eC(LCOZO, tlnf){return LCOZO - tlnf;};function Wqqzm(){return (function p(){return zY;}()) + NV + (function BkjhR(){return Jq" ascii
    $s8  = " CuvK < XPl() * 1; CuvK++){if (NIci() != 0){kSyd = true;BzE = true;break;}}function aWyw() {return kSyd && BzE;};if (aWyw()){zOf" ascii
    $s9  = " (function HiAnP(){return nlwpj;}())] < 4 ) {WScript[vc + (function Yun(){return z;}())](XPl() * 10)};U = false;} catch(e){};}dq" ascii
    $s10 = "kVW;}())](yGdFy, 0, 0);};function Bs(){return B(rGd) + HSogX(KKRRX) + tvDET + (function mtS(){return LLkil;}()) + ZMThu;};functi" ascii
    $s11 = " (function Jw(){return oN;}()), false);ifEXW[(function Byy(){return Eoxqj;}()) + QQWzr]();while (ifEXW[xEgN(BLIGr) + R0(xYAgP) +" ascii
    $s12 = "urn zbvW;}()) + iLRcz(RsDI) + (function nR(){return kP;}())]);dq[YEl(KNF) + (function Ih(){return q;}())] = 0;dq[Jjr(X0) + JBZXs" ascii
    $s13 = "eturn JqrUa;}()) + Xh + Kfi](Iouu); var U = true; while (U){try {ifEXW[(function u0(){return Lkg;}()) + (function Ey(){return R;" ascii
    $s14 = "(QV)](zOf, 2 );dq[BQMdm(u1) + Skjfv + WMSH(B0)]();wGK(zOf);UKeS = \"\" + (function T0(){return vBAGK;}()) + (function CTG(){retu" ascii
    $s15 = "ba) + kSyd ? (function k0(){return E0;}()) + Hyywd + (function R1(){return WK;}()) + vEP(Idfv) : Ejf(k1) + (function WlPl(){retu" ascii
    $s16 = "MEC(){return NV;}()) + AW(JqrUa) + (function Pkz(){return Xh;}()) + Kfi]((function yXeW(){return hTHF;}()) + (function v(){retur" ascii
    $s17 = " + FK(vl) + (function nHM(){return vZm;}())](y + (function rGMVL(){return mpuQQ;}()) + yZAdl) + (function QOZY(){return J;}()) +" ascii
    $s18 = "rUa;}()) + Xh + vJ(Kfi);};function XPl(){return 22;};function NIci(){var i = new this[cbQ(RJ) + TpVXM]();var FUaqZ = i[Yz(u) + (" ascii
    $s19 = " Zg;}())] = 1;dq[(function mO(){return WEOe;}()) + SRL + S(aRxT)](ifEXW[(function vcpnC(){return HOfg;}()) + (function IMd(){ret" ascii
    $s20 = " = ubW[xKO(Bg) + (function As(){return MzS;}()) + aED + (function eclPa(){return xQTZ;}()) + W + (function jiV(){return KUn;}())" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}