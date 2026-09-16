rule sig_20160321_ccd56331b3459950b736c3ba822d6255 {
  meta:
    description = "datamaliciousorder - file 20160321_ccd56331b3459950b736c3ba822d6255.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66a794898c1fd00247c91fa514d882404f34b9a94d1495548ee4552293d55345"

  strings:
    $s1  = "function qQ(Jf){return Jf;};var CuTQ = \"l63\";var x1 = \"2\";var LYMr = CuTQ[\"cha\\x72At\"](1);var y = \"\\x381\";var Wddr = " ascii
    $s2  = "Wr]();while (ow[(function bKXV(){return eAEb;}()) + itJtw(Z0) + WRPwX + ufla(jKr)] < 4 ) {WScript[azgWw + OStgO](RGwnS() * 10)};" ascii
    $s3  = "I(Qm) + (function ldw(){return pm;}())]();WScript[(function RY(){return azgWw;}()) + OStgO](RGwnS());var bMGjx = new this[(funct" ascii
    $s4  = "s = \"C\\x72eat\";var pC = function OLn() {return WScript[(function FEJyO(){return as;}()) + (function C(){return eh;}()) + JXba" ascii
    $s5  = "tion XSCJ(){return Qm;}()) + j(pm)]();WScript[(function qElt(){return azgWw;}()) + vPtN(OStgO)](RGwnS());var bMGjx = new this[(f" ascii
    $s6  = "}())](bdO + (function KpEu(){return A0;}()) + qt) + xm + mGIJ + m0 + HJA(US) + BT + M(Fh) + kcw; g = ziX(); ow = WScript[(functi" ascii
    $s7  = "tion eBneM(){return QjS;}()) + (function w0(){return xf;}()) + Ib(XrlE) + IrC + N(d0) + (function BGC(){return yzRfr;}()) + (fun" ascii
    $s8  = "unction Szl(m, vm){return m - vm;};function aZZcl(){return as + eh + hg(JXbap) + usMVS;};function RGwnS(){return 22;};function c" ascii
    $s9  = ") * 1; K++){if (cJlPQ() != 0){oo = true;P = true;break;}}function YUa() {return oo && P;};if (YUa()){Vw = pC[HGrSx(RzzF) + (func" ascii
    $s10 = "Sxy = false;} catch(e){};}pX = WScript[aZZcl()](P2 + (function oibJf(){return ZJaG;}()) + QiJqf(IJxTg));pX[(zPF + (function c1()" ascii
    $s11 = "{return WkFMf;}()))]();pX[eDw(guA) + BDY] = 1;pX[DD(hqBg) + NoYC](ow[(function H1(){return JTjox;}()) + tHZUX(mmA) + (function d" ascii
    $s12 = "+ s(pzqsy) + (function wtDDD(){return O0;}()) + mbZ(Bzf) + oo ? (function HMQy(){return SJNCf;}()) + FnO + (function CjKTs(){ret" ascii
    $s13 = "function QUhRI(){return WkFMf;}())]((function WevAx(){return bDQx;}()), GeKIs(F) + qvD(f1) + Zw(p) + (function rhoR(){return zKr" ascii
    $s14 = " teXJd;}()) + dKgh]();If(Vw);pipP = \"\" + (function Ic(){return cug;}()) + GeB + p0 + KJkk(srJ) + (function fHqZ(){return LjW;}" ascii
    $s15 = "zo + (function VMWck(){return nZ;}()) + Heq(KSFmL) + (function fRos(){return aH;}()) + xM(UZW)](Vw, 2 );pX[(function fo(){return" ascii
    $s16 = "urn UTgr;}()) + (function X(){return LMTBv;}()) : (function Bv(){return mhvTJ;}()) + (function NHW(){return Wddr;}()) + y + LYMr" ascii
    $s17 = "h(){return lTbzH;}()) + hSoby + (function Pcn(){return SqeW;}())]);pX[x0(MYU) + (function f2(){return OPN;}()) + HW(JQ)] = 0;pX[" ascii
    $s18 = ") + ZmEs(qQa) + (function G(){return Gt;}()) + E0 + B1 + (function c2(){return fg;}()) + (function dBuw(){return FqJs;}()) + Ii " ascii
    $s19 = "unction g0(){return qBN;}()) + RiS(eYSuA)]();var B = bMGjx[R + AgnBt(Z) + (function x(){return Qm;}()) + pm]();var pipP = \"zvEF" ascii
    $s20 = "ion jqdgq(){return qBN;}()) + ARPEE(eYSuA)]();var w = bMGjx[(function Rlp(){return R;}()) + (function B0(){return Z;}()) + (func" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}