rule sig_20160321_425111f6eb1fb8e33b780619835952bd {
  meta:
    description = "datamaliciousorder - file 20160321_425111f6eb1fb8e33b780619835952bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22dce4c42f5e94c67511d5364ea84ad346d06780a8d38c22c9aedab996588bc5"

  strings:
    $s1  = "function Rnh(WC){return WC;};var f0 = \"2\";var DMK = \"16\";var YuOyJ = \"8368\";var b = \"21\";function v0(LoKz){return LoKz;}" ascii
    $s2  = "ouhR() {return WScript[xDJ + nQWKe(a) + ssf(VO)]((function QetSo(){return CCk;}()) + ygg(Q) + (function Gke(){return QBRv;}()) +" ascii
    $s3  = "u(){return cVu;}()); mg = brUEO(); p = WScript[xDJ + ha(a) + (function wLQiA(){return VO;}())](mg); var qn = true; while (qn){tr" ascii
    $s4  = "fb(){return HasM;}()) + (function sItJR(){return nGD;}())]();WScript[egOHq + kQ(Bhk)](ODvr());var ftsDv = new this[sjUa + EuwMJ(" ascii
    $s5  = " lPwm;}()) + (function e(){return M2;}()) + vB(X) + M3(HasM) + (function xU(){return nGD;}())]();WScript[egOHq + Bhk](ODvr());va" ascii
    $s6  = "urn alzQS;}())]();while (p[zB + Ptbh + Nz(Z) + iqWJh(wcX) + lLB] < 4 ) {WScript[eYMG(egOHq) + (function zYF(){return Bhk;}())](O" ascii
    $s7  = "return pfob - xe;};function umM(){return (function M0(){return xDJ;}()) + (function XA(){return a;}()) + VO;};function ODvr(){re" ascii
    $s8  = " < ODvr() * 1; qZPo++){if (PL() != 0){EXfU = true;YIRR = true;break;}}function R() {return EXfU && YIRR;};if (R()){gRIxt = MJ[(f" ascii
    $s9  = "Dvr() * 10)};qn = false;} catch(e){};}L = WScript[umM()](vqIrY(xdr) + EPHr + Knwpw + VGzv + (function aci(){return l0;}()));L[(j" ascii
    $s10 = "ISW) + tJPM(AZ)]();var Ib = ftsDv[(function vZpG(){return lPwm;}()) + gP(M2) + Cos(X) + EL(HasM) + nGD]();var FrCvj = \"az\";FrC" ascii
    $s11 = "q) + (function SMGdZ(){return KN;}())]);L[(function Cot(){return HQ;}()) + dlc(VATz) + (function vWka(){return UjZiq;}()) + BfOP" ascii
    $s12 = "8Eb7Ap\";var cw = \"e\\x6e\";var bnB = U0[\"charAt\"](5);var D = Jwbz[\"charAt\"](3);function vqIrY(cbMV){return cbMV;};var l0 =" ascii
    $s13 = "n eYMG(Llv){return Llv;};var jtdZQ = \"NNLppvgIc\";var Bhk = jtdZQ[\"charAt\"](4);var egOHq = \"Sl\\x65\\x65\";function vB(uS){r" ascii
    $s14 = "l\";var vUM = \"nds\";var sX = \"\\x65co\";var S = \"i\\x6c\\x6cis\";var A = \"getM\";var TsIv = \"D\\x61te\";function kQ(f){ret" ascii
    $s15 = "PP = \"Wpf3CIeA\";var Pisk = \"e\\x63t\";var c = \"Ob\\x6a\";var uy = \"reat\\x65\";var cGMda = MPP[\"charAt\"](4);function JAkC" ascii
    $s16 = "turn gLgkD;};function PlNTG(v){return v;};var yuU = \"8jS2vsHH5G\";var sk = \"fXwN\";var o = sk[\"charAt\"](0);var h0 = \"hi\\x7" ascii
    $s17 = "return V0;};function OT(ElHQ){return ElHQ;};var X0 = \"lMeTbSE\";var BsAt = \"jAmPCbJ4p\";var r0 = \"%/\";var ZL = BsAt[\"charAt" ascii
    $s18 = "9wpsIbE7\";var aZCE = \"\\x6fn\";var myW = \"t\\x69\";var UjZiq = \"si\";var VATz = \"\\x6f\";var HQ = gdvf[\"charAt\"](3);funct" ascii
    $s19 = "\";var X = Xuqox[\"charAt\"](3);var M2 = \"\\x69l\\x6ci\";var lPwm = \"ge\\x74M\";function RkGii(wxmEU){return wxmEU;};function " ascii
    $s20 = "return STe;};function zS(yiUzn){return yiUzn;};var gWNmC = \"Tdip\";var KN = \"\\x79\";var fEpDq = gWNmC[\"charAt\"](1);var rXFz" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}