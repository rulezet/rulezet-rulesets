rule sig_20160323_08b30a409ccc0c4a24accf29ca4f8d90 {
  meta:
    description = "datamaliciousorder - file 20160323_08b30a409ccc0c4a24accf29ca4f8d90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ee732b45c6f042816f9f90fa7e1ea169efe9118d4d27939c4e9d2f015657dbc"

  strings:
    $s1  = "function hOF(W0){var _112crap = \"s\"; return \"\" + W0 + \"\";};function xI(y){var _112crap = \"s\"; return \"\" + y + \"\";};v" ascii
    $s2  = " h0(); o0 = WScript[e + dAl(uox) + nM](B); var D = true; while (D){try {o0[Sn(PzV) + qC](SG(QS) + BqF(VPm) + v(z1), aW(q) + il +" ascii
    $s3  = "+ u](WTv());var UwR = new this[ZKg](),ck = UwR[jqU + f1(tH) + Ejv(W) + ae(C0) + U0(Es) + H(aO)]();WScript[Jiv(YA) + hxp(u)](WTv(" ascii
    $s4  = "= 0;function h(){var UwR = new this[ZZ(ZKg)](),Cu = UwR[Fn(jqU) + uJ(tH) + Q(W) + nfh(C0) + PBD(Es) + J0(aO)]();WScript[ERM(YA) " ascii
    $s5  = "+\"arAt\"](5);function Sn(th){var _112crap = \"s\"; return \"\" + th + \"\";};function Rx(bF){var _112crap = \"s\"; return \"\" " ascii
    $s6  = "turn \"\" + i1 + \"\";};var V = \"6dsd3\",zN = \"fR6xAe\";var D1 = zN[\"c\"+\"\\x68\"+\"arAt\"](5),s = \"t\\x61\\x74\";var RLD =" ascii
    $s7  = "rn \"\" + FgY + \"\";};function SR(C){var _112crap = \"s\"; return \"\" + C + \"\";};var I0 = \"9FPV\",zLo = I0[\"c\"+\"\\x68\"+" ascii
    $s8  = "E = \"\\x6fsit\\x69\",X4 = Ej[\"c\"+\"\\x68\"+\"arAt\"](5);function Ira(iTV){var _112crap = \"s\"; return \"\" + iTV + \"\";};va" ascii
    $s9  = "rAt\"](5),fF = \"\\x38\";function eT(S){var _112crap = \"s\"; return \"\" + S + \"\";};var K1 = \"%/\",k5 = \"MP\";var X0 = \"" ascii
    $s10 = "8\"+\"arAt\"](1),A2 = \"t\";var ZCB = \"\\x72i\",ss = Sa[\"c\"+\"\\x68\"+\"arAt\"](2);function IBc(lK){var _112crap = \"s\"; ret" ascii
    $s11 = ";};function FNU(Gi){var _112crap = \"s\"; return \"\" + Gi + \"\";};var ABu = \"YqFjexE8ZJ\",f3 = ABu[\"c\"+\"\\x68\"+\"arAt\"](" ascii
    $s12 = "Uv = ZDK[\"c\"+\"\\x68\"+\"arAt\"](1),vY = \"\\x44\";function ERM(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};function J" ascii
    $s13 = "};function FH(AJ){var _112crap = \"s\"; return \"\" + AJ + \"\";};var nP = \"zTV6xtgO\",ULV = \"VeSg0E\";var jz = ULV[\"c\"+\"" ascii
    $s14 = ", 0);};function h0(){return FzG(c) + tyi + zjC + Oe(Yx) + SR(zLo);};function yNN(k0, z){return k0 - z;};function Tl(){return jpY" ascii
    $s15 = "(jTf == Edf) && (jTf == true)) ? true : false;};if (jTf && sCi() && Edf){function lzN() {return mMj[UIa + x + KI(gWq) + j(kVu) +" ascii
    $s16 = "\"](2),GU = \"read\\x79\";function T(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function GH(LBN){var _112crap = \"s\"; " ascii
    $s17 = "rap = \"s\"; return \"\" + gs + \"\";};var ZYf = \"e\\x61\\x6d\",TQ = \"\\x42.Str\";var U2 = \"OD\",Vjh = \"AD\";function sz(gK)" ascii
    $s18 = ");while (o0[GU + A1(RLD) + MQQ(s) + D1] < 4 ) {WScript[VqX(YA) + QZE(u)](WTv() * 10)};D = false;} catch(AW){D = (n(Wg) + X2(F0)," ascii
    $s19 = "c = NK[\"c\"+\"\\x68\"+\"arAt\"](3),qEg = \"Objec\";var w = \"r\\x65at\\x65\",gw = cgX[\"c\"+\"\\x68\"+\"arAt\"](4);function iNP" ascii
    $s20 = "),SFw = \"yp\";var Tk = nP[\"c\"+\"\\x68\"+\"arAt\"](5),GH0 = \"4X40ooz\";var aM = \"pe\\x6e\",hNx = GH0[\"c\"+\"\\x68\"+\"arAt" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}