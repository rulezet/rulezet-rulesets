rule sig_20160321_7d9e7c2eca7ee0cdbe0b2c562380352c {
  meta:
    description = "datamaliciousorder - file 20160321_7d9e7c2eca7ee0cdbe0b2c562380352c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf799ee2be92cd23e2076b79026fe660a558e1eb1635dff7da1dcf2ad8052302"

  strings:
    $s1  = "function uJv(o){return o;};var nSKCh = \"6TH\";var TWey = \"8\\x3162\";var eKewj = nSKCh[\"char\\x41t\"](0);var mX = \"2183\";fu" ascii
    $s2  = " \"za\";var xIhhc = \"/\\x2f\";var hnaRy = \"http:\";function A(Pc){return Pc;};var m0 = \"GET\";function MVp(Fyl){return Fyl;};" ascii
    $s3  = "= function wkq() {return WScript[F + (function Pbi(){return gC;}()) + (function F0(){return OcQ;}()) + vhNef](NE + PT(ozmxg) + b" ascii
    $s4  = "w(GYchg) + TCQtk + Zba + (function jdqxD(){return R1;}()) + hcgP(Ex) + wADW; h = iCYbT(); yEjs = WScript[(function vigkq(){retur" ascii
    $s5  = "nction t(){return b;}()) + (function PZF(){return ONM;}()) + sf(b0) + D + (function nPXMh(){return ttg;}()) + Gxf]();WScript[(fu" ascii
    $s6  = " LZP(ajhOJ) + GGYTQ(QUnuy), false);yEjs[PCG(skh)]();while (yEjs[XQrl(zbwx) + QcdAo(ejVSS) + Ax0(sXn) + ONvGA] < 4 ) {WScript[(fu" ascii
    $s7  = ")) + (function sWxOS(){return ODsbH;}()) + CzDm(wKL) + oKMJ;};function QA(pb, bF){return pb - bF;};function dg(){return Ugwgr(F)" ascii
    $s8  = "TNRyg = true;break;}}function fJyLt() {return cXdq && TNRyg;};if (fJyLt()){n = IUJT[(function hTBRM(){return YvfP;}()) + s(yJB) " ascii
    $s9  = "nction exoF(){return bVvp;}())](a() * 10)};wA = false;} catch(e){};}g = WScript[dg()](n0(BPBy) + XLSt(h0) + E1 + (function sF(){" ascii
    $s10 = "5at\";var UtlGG = \"Cr\";function CzDm(xOql){return xOql;};var UJH = \"ll.BYrHJ\";var Vjne = \"N4xfTP4I\";var oKMJ = Vjne[\"char" ascii
    $s11 = "= \"get\";function S0(qju){return qju;};var a0 = \"ate\";var twZoO = \"\\x44\";var msQzn = \"e\\x63\\x74\";var Oa = \"eObj\";var" ascii
    $s12 = "nction tmeRf(){return bVvp;}())](a());var OII = new this[twZoO + (function LRzYM(){return a0;}())]();var X = OII[(function BXzHD" ascii
    $s13 = " V(){return yKtLW;}()) + lAE(c1) + oY(E2) + (function le(){return wOWEC;}())]);g[JEbuS(byoW) + (function jB(){return LMUZI;}()) " ascii
    $s14 = "(){return b;}()) + ONM + ikGS(b0) + D + ttg + Gxf]();var jf = \"xuubb\";jf = QA(iYtbJ, qcFr);var lBO = \"TaxXb\";lBO = QA(X, iYt" ascii
    $s15 = "n eKewj;}()) + (function FQvfF(){return TWey;}());}" fullword ascii
    $s16 = "xEBt;}())](A(m0), Qkk(hnaRy) + (function yF(){return xIhhc;}()) + rCG(U) + qr + (function RL(){return rch;}()) + c + MVPWb(F1) +" ascii
    $s17 = "ipt[VZry(bVvp)](a());var OII = new this[(function KNdf(){return twZoO;}()) + (function R(){return a0;}())]();var iYtbJ = OII[(fu" ascii
    $s18 = "RB + (function YbI(){return Hvy;}()) + (function KJLd(){return ehMR;}()));}();function UGMrm(AtQ){IUJT[rmK(Oh) + PhDO(jn)](AtQ, " ascii
    $s19 = "return QA(jf, lBO);}var cXdq = false;var TNRyg = false;for (var hMZWi = 0; hMZWi < a() * 1; hMZWi++){if (pK() != 0){cXdq = true;" ascii
    $s20 = "()) + (function z0(){return xU;}()) + cXdq ? Qdw + (function LHFv(){return QfGW;}()) + TJ(g0) : uJv(mX) + (function AGXG(){retur" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}