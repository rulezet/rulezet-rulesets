rule sig_20160321_43721e3428f5330826a6444669c21708 {
  meta:
    description = "datamaliciousorder - file 20160321_43721e3428f5330826a6444669c21708.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b37c004b9bc12b216ab3b2e347920b9b2152b9e6d296898a2b0ae8c3619078ab"

  strings:
    $s1  = "k(aU) + rG + cra(wZeG) + (function gQ(){return CcG;}()) + g + VKKKL; nkHQz = X(); IC = WScript[F + Ad(YKve) + (function HY(){ret" ascii
    $s2  = " w(XYH) + (function PuA(){return rQMn;}())]();WScript[YZu(xbJaM) + (function z(){return n;}())](idnUB());var mXUzb = new this[(f" ascii
    $s3  = "function Ffxq(ZE){return ZE;};var Ku = \"81\\x362\";var NmZ = \"\\x38\\x336\";var GjI = \"21\";var VTGBK = \"\\x73df\";var Z = " ascii
    $s4  = "ion E0(){return hri;}())]();while (IC[ea + m(rDE) + YRDA] < 4 ) {WScript[(function zmXFQ(){return xbJaM;}()) + n](idnUB() * 10)}" ascii
    $s5  = "unction e(){return SMxsV;}())]();var rZxl = mXUzb[Rm(XYKMW) + dz(mEkpp) + QN(XYH) + (function uYtl(){return rQMn;}())]();WScript" ascii
    $s6  = "turn mj - bTXO;};function Yp(){return Bjj(F) + (function thIl(){return YKve;}()) + Sc(Kupv);};function idnUB(){return 22;};funct" ascii
    $s7  = "c = true;break;}}function AU() {return aA && Zgc;};if (AU()){qfb = TyOxi[gM(W) + (function b(){return lUbyY;}()) + Kc(EWl) + L1(" ascii
    $s8  = ";Qn = false;} catch(e){};}UP = WScript[Yp()]((function lj(){return EH;}()) + (function uOnFx(){return qvhm;}()) + o0(Gp) + iIx +" ascii
    $s9  = "}()) + bUOh + (function iA(){return bClVm;}()) + vo + cNX(gs)]);UP[yV + (function Udpzu(){return BYMg;}()) + fbIUv] = 0;UP[(func" ascii
    $s10 = "G;}()) + mE + HxtG + aA ? OB + Z + (function Dw(){return VTGBK;}()) : (function Hd(){return GjI;}()) + Ffxq(NmZ) + (function Zq(" ascii
    $s11 = ";szv = \"\" + kM + (function jQe(){return jUb;}()) + OgfRu(w0) + (function PQfZB(){return q;}()) + cgN + x0(cg) + Aopm + (functi" ascii
    $s12 = "H(){return tJgtz;}()) + J(iVSR) + (function i(){return ZENcy;}()) + (function r1(){return CiHG;}());};function OifB(mj, bTXO){re" ascii
    $s13 = "ion mV(){var mXUzb = new this[(function E(){return SMxsV;}())]();var d = mXUzb[(function Cb(){return XYKMW;}()) + UxJlG(mEkpp) +" ascii
    $s14 = "pt[F + (function IYU(){return YKve;}()) + (function Qs(){return Kupv;}())](r(hnA) + LiX + WXs(goWR) + WJjv(o) + DEf(OJqHH) + uwX" ascii
    $s15 = "OS) + JDw(PlJoN) + wLQM(hDDB) + (function hZZ(){return H;}())](K0(cfrK) + (function wKdaR(){return Cfgc;}())) + DZb(cNBBQ) + hsa" ascii
    $s16 = "(rFIN));}();function WeNW(j){TyOxi[LEtN(xbN)](j, 0, 0);};function X(){return r0(duLd) + fXj(PjJM) + tOz + gVE + XP + (function l" ascii
    $s17 = "[(function jsMmE(){return xbJaM;}()) + n](idnUB());var mXUzb = new this[SMxsV]();var POD = mXUzb[XYKMW + XkI(mEkpp) + (function " ascii
    $s18 = " (function uWTso(){return nfjBY;}()));UP[(ZIP(cGcgA))]();UP[GkV(cuy)] = 1;UP[X1(enmUR) + fzvsI](IC[(function zgoDv(){return LnQ;" ascii
    $s19 = "tion x(){return rkU;}()) + o1 + LP(N) + (function vZ(){return Bo;}())](qfb, 2 );UP[AZEHj(nR) + fo(OAOb) + PDrW(Vug)]();WeNW(qfb)" ascii
    $s20 = "yJ(M) + Od + H0 + ku + HkDp + (function S(){return ZLU;}()) + n0 + (function PliAR(){return STa;}()) + Y1(kif), false);IC[(funct" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}