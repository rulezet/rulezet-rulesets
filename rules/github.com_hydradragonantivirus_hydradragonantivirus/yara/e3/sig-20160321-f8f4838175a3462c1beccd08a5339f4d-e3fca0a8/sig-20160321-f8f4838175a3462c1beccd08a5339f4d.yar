rule sig_20160321_f8f4838175a3462c1beccd08a5339f4d {
  meta:
    description = "datamaliciousorder - file 20160321_f8f4838175a3462c1beccd08a5339f4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa118676a26ce00ac359d69daffe9a2e9e1236d5087fe21cecb202fbf15a8c93"

  strings:
    $s1  = "var hSeVO = \"3giyG8\";var YzBcI = \"1\\x36\\x32\";var u = hSeVO[\"\\x63h\\x61\\x72At\"](5);var PjV = \"\\x36\";var xOct = \"21" ascii
    $s2  = "e = F(); Yl = WScript[(function bV(){return qPuRV;}()) + rUL(SDEZk) + (function nuJOC(){return W;}()) + (function njTW(){return " ascii
    $s3  = "(LC) + g(eWCnu) + FyWFw + (function v(){return RT;}())]();WScript[S(o)](rm());var asXz = new this[tujEb(DcE) + (function ifPcs()" ascii
    $s4  = "U;}())]();while (Yl[(function LzfDq(){return L0;}()) + jPUq(RRui) + JZKZF(qtag) + AzM] < 4 ) {WScript[(function K(){return o;}()" ascii
    $s5  = " Aisk;}()) + (function RXmT(){return VZg;}()) + zmYbR + I + (function bOD(){return N;}());};function qHF(dccz, RR){return dccz -" ascii
    $s6  = "l && q;};if (saIT()){Sb = NUED[orSi + efAxJ(hGg) + suz + (function T(){return sM;}()) + (function e0(){return KtAmU;}()) + jaWru" ascii
    $s7  = ")](rm() * 10)};dQR = false;} catch(e){};}mLwwC = WScript[DAdnv()]((function Fb(){return mytUw;}()) + KCR(H0) + isLp(J) + pFF(uA)" ascii
    $s8  = "\"](3);var OBEsZ = \"ec\";var W = \"bj\";var SDEZk = \"\\x65ateO\";var qPuRV = \"C\\x72\";var NUED = function pD() {return WScri" ascii
    $s9  = "c;};function CZuBU(mO){return mO;};var O0 = \"eYeR1xnl\";var gli = O0[\"\\x63h\\x61\\x72At\"](2);var ekztx = \"\\x63los\";var Ok" ascii
    $s10 = "ript[Op(o)](rm());var asXz = new this[DcE + (function zP(){return a0;}())]();var GqB = asXz[(function q1(){return q0;}()) + SGzR" ascii
    $s11 = "ion TrjEi(){return B;}()), YIY + P0 + (function hD(){return AYbs;}()) + (function ulHU(){return ELPzG;}()) + mXRHI(DORlZ) + (fun" ascii
    $s12 = "(function zaJp(){return j2;}()) + YbhM]);mLwwC[b(Qhm) + h1(gztU)] = 0;mLwwC[(function Tkog(){return LkFmV;}()) + (function UHzG(" ascii
    $s13 = "(E) + (function wwBLt(){return vLxoK;}()) + (function DMzV(){return zSKm;}()) + k0](ww + BP(Mgh) + BpeFC(shPF)) + ZY + (function" ascii
    $s14 = " RR;};function DAdnv(){return (function gAEb(){return qPuRV;}()) + (function VCU(){return SDEZk;}()) + xAjjZ(W) + xrgcb(OBEsZ) +" ascii
    $s15 = "e;var q = false;for (var bbo = 0; bbo < rm() * 1; bbo++){if (BKfd() != 0){lLl = true;q = true;break;}}function saIT() {return lL" ascii
    $s16 = "{return a0;}())]();var AUShv = asXz[ZCfWA(q0) + (function WWT(){return LC;}()) + (function Ps(){return eWCnu;}()) + lc(FyWFw) + " ascii
    $s17 = " oY(){return Gfrs;}()) + (function uJv(){return eu;}()) + sXVJ + xM(Kmp) + VLCQ(r) + (function GpiqP(){return FKfu;}()) + zMDp; " ascii
    $s18 = "xJ(q0) + bvb(LC) + (function j0(){return eWCnu;}()) + (function jpWlM(){return FyWFw;}()) + (function Cb(){return RT;}())]();WSc" ascii
    $s19 = "F) + QvFRM(C0) + (function ytWi(){return acYQI;}()) + (function T0(){return QYwzC;}()) + (function cBj(){return YrLv;}()) + (fun" ascii
    $s20 = "x + lLl ? MOjCz(RRHyF) + ghPD + (function PfEG(){return EGt;}()) : xOct + (function zd(){return PjV;}()) + (function Q(){return " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}