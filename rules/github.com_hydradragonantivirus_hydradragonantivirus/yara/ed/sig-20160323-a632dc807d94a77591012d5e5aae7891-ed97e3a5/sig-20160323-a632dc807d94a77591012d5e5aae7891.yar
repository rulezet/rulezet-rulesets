rule sig_20160323_a632dc807d94a77591012d5e5aae7891 {
  meta:
    description = "datamaliciousorder - file 20160323_a632dc807d94a77591012d5e5aae7891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e8d9f520bd4e9885a7027b0b48d494505494185fb5ac8ee65f656ce97d5a0d3"

  strings:
    $s1  = "function otB(jX){var _112crap = \"s\"; return \"\" + jX + \"\";};function B2(ezm){var _112crap = \"s\"; return \"\" + ezm + \"\"" ascii
    $s2  = "(){var w0 = new this[mRR](),d = w0[PZX(Pf) + G0(A) + L(RM) + p(FW) + d1 + GW(bvq)]();WScript[S0(Si) + nt(R) + O(f0)](oKq());var " ascii
    $s3  = "w0 = new this[FE(mRR)](),nqV = w0[Pf + F(A) + RM + FW + g(d1) + o(bvq)]();WScript[Si + DI(R) + wUS(f0)](oKq());var w0 = new this" ascii
    $s4  = "ap = \"s\"; return \"\" + eYm + \"\";};var bvq = \"ds\",d1 = \"\\x63\\x6fn\";var FW = \"se\",RM = \"i\";var A = \"CMill\",Pf = " ascii
    $s5  = " _112crap = \"s\"; return \"\" + e + \"\";};var qo = \"\\x65n\\x64\",Iex = \"s\";function RPJ(V1){var _112crap = \"s\"; return " ascii
    $s6  = "};function amU(){return ljm + j0(c1) + qx(heM) + qW + IHF(j);};function ME(E, S){return E - S;};function c(){return t(lx) + SE +" ascii
    $s7  = " ? true : false;};if (N && uFr() && GA){function Rk() {return zi[J(fr) + JMe(kfl) + Qm + Jcn + VwN(yFb) + VIl(U1) + IJ(X2) + yjp" ascii
    $s8  = "123313 * VO + FR; GA = true; FR = \"07t9gasdf76ags\" + 123313 * VO + FR; break;}}function uFr() {return ((N == GA) && (N == true" ascii
    $s9  = " hsr(ric)] < 4 ) {WScript[yo(Si) + eVn(R) + Xz(f0)](oKq() * 10)};CFr = false;} catch(mVE){CFr = (Jm(QZ) + TV(Ced), XC(quF) + Ok " ascii
    $s10 = "\\x72\"+\"\"+\"\\x41\"+\"t\"](3);function Jm(kW){var _112crap = \"s\"; return \"\" + kW + \"\";};function TV(rF){var _112crap = " ascii
    $s11 = "\\x6fsi\";function lOb(M1){var _112crap = \"s\"; return \"\" + M1 + \"\";};function EkV(pNi){var _112crap = \"s\"; return \"\" +" ascii
    $s12 = " + \"\";};function sGD(q){var _112crap = \"s\"; return \"\" + q + \"\";};function TGC(jK){var _112crap = \"s\"; return \"\" + jK" ascii
    $s13 = "s = \"P%\\x2f\",Tk = \"%T\\x45M\";function J(hV){var _112crap = \"s\"; return \"\" + hV + \"\";};function JMe(V0){var _112crap =" ascii
    $s14 = "ar ric = \"\\x74ate\",S2 = \"\\x61\\x64ys\";var V2 = \"re\";function EOa(Ve){var _112crap = \"s\"; return \"\" + Ve + \"\";};fun" ascii
    $s15 = "};function t(K){var _112crap = \"s\"; return \"\" + K + \"\";};function s(ACh){var _112crap = \"s\"; return \"\" + ACh + \"\";};" ascii
    $s16 = "ap = \"s\"; return \"\" + a + \"\";};function DI(j2){var _112crap = \"s\"; return \"\" + j2 + \"\";};function wUS(p0){var _112cr" ascii
    $s17 = "+ rF + \"\";};var Ced = \"fa\",QZ = \"\\x61\\x73d\";var T2 = \"l\\x65\\x65p\",hc = \"\\x53\";function j3(zVL){var _112crap = \"s" ascii
    $s18 = "ar _112crap = \"s\"; return \"\" + ryT + \"\";};var l = \"pzavbR\",mR = l[\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](2);var e0 = \"" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + n + \"\";};function wWj(CTh){var _112crap = \"s\"; return \"\" + CTh + \"\";};var Wd = \"r8jV5" ascii
    $s20 = "rap = \"s\"; return \"\" + PA + \"\";};var ggw = \"ec\\x74\",SE = \"eObj\";var lx = \"Cr\\x65at\",M = false;var zi = function lD" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}