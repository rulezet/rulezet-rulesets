rule sig_20160321_706440d4efee6bc0ebe8e9388163f34b {
  meta:
    description = "datamaliciousorder - file 20160321_706440d4efee6bc0ebe8e9388163f34b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fa906790569bd06e9b4ae65225b989ca29d411fd946eaf7f49816d0a2c174ce"

  strings:
    $s1  = "function kIioH(Sej){return Sej;};function iCgMZ(WMPIZ){return WMPIZ;};var juEDt = \"\\x381\\x362\";var R0 = \"\\x336\";var dCK =" ascii
    $s2  = "X(){return Vz;}()) + HhNet(w) + ided(Evxv) + C1; SLJ = v(); t = WScript[(function RGe(){return JIs;}()) + (function ez(){return " ascii
    $s3  = "D;}()) + qgX(YE)]();WScript[SEOon + (function lJDV(){return RuV;}())](vpXRx());var Y = new this[PYudt]();var C = Y[dbRre(mvxp) +" ascii
    $s4  = " wYc = function Zy() {return WScript[Y0(JIs) + bF + (function W(){return UkDQa;}()) + (function qO(){return KlNq;}()) + (functio" ascii
    $s5  = " GJId(Uni) + qQsU + eDnG + OrUy + (function E(){return LDXD;}()) + (function JT(){return YE;}())]();WScript[(function r0(){retur" ascii
    $s6  = "turn I;}()) + lVam(gRoWq) + QBqY(wqdo)]();while (t[(function ZnzQk(){return E2;}()) + dK + He(M0) + F0(r1)] < 4 ) {WScript[GpxS(" ascii
    $s7  = "+ (function R(){return hpUAU;}());};function F(UWC, jBkH){return UWC - jBkH;};function lQgE(){return JIs + bF + Ckz(UkDQa) + (fu" ascii
    $s8  = "jo() != 0){We = true;rF = true;break;}}function U() {return We && rF;};if (U()){H = wYc[NBFjM + PYclO + jl + bZf(x) + (function " ascii
    $s9  = "SEOon) + zpTv(RuV)](vpXRx() * 10)};lY = false;} catch(e){};}eB = WScript[lQgE()]((function YZZ(){return wpakw;}()) + Nwb + (func" ascii
    $s10 = "nction LSG(){return KlNq;}()) + nGv;};function vpXRx(){return 22;};function APjo(){var Y = new this[ECvbz(PYudt)]();var uuBh = Y" ascii
    $s11 = "x0(){return HFi;}()) + (function Gxu(){return MvIv;}()) + eWjqa(dbrLF) + Xz(H0)]);eB[O1 + fbMsm(acU)] = 0;eB[gan(pGvgP) + (funct" ascii
    $s12 = "tion BwgsQ(){return acpP;}()) + wR(wj) + f0(VY) + xmrio + cWf + Say(Oj) + QXw(lGnM));eB[((function cNsdZ(){return QrHck;}()))]()" ascii
    $s13 = "vxp;}()) + cO(Uni) + (function CIy(){return qQsU;}()) + eDnG + M(OrUy) + LDXD + sIUaQ(YE)]();var Vy = \"da\";Vy = F(C, uuBh);var" ascii
    $s14 = "n SEOon;}()) + NnA(RuV)](vpXRx());var Y = new this[(function sNXRq(){return PYudt;}())]();var AUgn = Y[(function mjku(){return m" ascii
    $s15 = "lpz(){return rFJnD;}()) + (function RlQK(){return JgPSq;}()) + (function nnE(){return LWL;}()) + (function N(){return NYFW;}()) " ascii
    $s16 = "IAzr(){return Fy;}()) + (function v0(){return rGTF;}()) + jnn(pV) + Rp(kUsP) + Wk(wRgH)](K(CPc) + xzXM(MCs)) + iGL + (function j" ascii
    $s17 = "+ (function AGSug(){return s0;}()) + (function aQKfu(){return RHwSl;}()) + C2(KwTk) + fB(mfr) + t0(KaEp) + xctV(SIYH) + We ? (fu" ascii
    $s18 = ") + (function sJERx(){return hkE;}()) + (function U0(){return pQLmU;}()) + lJvN + (function OXr(){return bAXF;}()));}();function" ascii
    $s19 = "function edRTH(){return n;}()) + zEm(MGKjJ) + CcfOH + (function CIa(){return PqHB;}()) + l + BWhtu, false);t[(function sUJq(){re" ascii
    $s20 = "n Lcght(){return nGv;}())]((function wWPC(){return oU;}()) + (function SkhpL(){return Yzzk;}()) + (function dNyBM(){return a;}()" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}