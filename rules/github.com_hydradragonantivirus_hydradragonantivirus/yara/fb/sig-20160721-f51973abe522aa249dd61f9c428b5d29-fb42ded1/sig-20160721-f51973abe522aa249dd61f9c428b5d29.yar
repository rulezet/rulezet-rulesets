rule sig_20160721_f51973abe522aa249dd61f9c428b5d29 {
  meta:
    description = "datamaliciousorder - file 20160721_f51973abe522aa249dd61f9c428b5d29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1b3ba7cdb80e8584bd587d05f7fd8e0edd9577e8a332f10ed5a539c30c38db4"

  strings:
    $s1  = "var Rr5=WScript[XJg(Dk) + Xs7 + GWu0](YQj7 + (function Ze0(){return VBf;}()) + MGx + Zn7);" fullword ascii
    $s2  = "    var LVk = WScript[Dk + Xs7 + GWu0](SUh + VMn + Xb8 + Uj0 + (function RBp9(){return CTr;}()) + UAy5 + PJz4 + Wc + Ka4);" fullword ascii
    $s3  = "var NOa2=Pf + NTy5(Tx5) + (function Oh(){return Hb7;}()) + (function OMj(){return Kk;}()) + Me3;" fullword ascii
    $s4  = "function NTy5(Ku){return Ku;};var Me3 = \"MJK\" + \"\";" fullword ascii
    $s5  = "function WFp0(AGe){return AGe;};var PRm = \"ile\" + \"\";" fullword ascii
    $s6  = "function VQr(Px9){return Px9;};function Ho(Sh){return Sh;};var Lk0 = \"ile\" + \"\";" fullword ascii
    $s7  = "function Ir(Vg){return Vg;};var LPw = \"am\" + \"\";" fullword ascii
    $s8  = "function RDj2(WWe7){return WWe7;};var Ss1 = \"t\" + \"\";" fullword ascii
    $s9  = "function Vi(TKi){return TKi;};function XJg(IDk5){return IDk5;};var GWu0 = \"ct\" + \"\";" fullword ascii
    $s10 = "function DLb(Ne){return Ne;};var RHz = \"en\" + \"\";" fullword ascii
    $s11 = "function Yx4(SJk){return SJk;};var NAy = \"ream\" + \"\";" fullword ascii
    $s12 = "function JLt(KOf0){return KOf0;};var ODl = \"ne\" + \"\";" fullword ascii
    $s13 = "function EXd2(RKj6){return RKj6;};var Ov = \"in\" + \"\";" fullword ascii
    $s14 = "function CBe6(KXv, Cn) {" fullword ascii
    $s15 = "function VTf(Dq, Cn)" fullword ascii
    $s16 = "   JBd = Sx[VQr(OEo) + (function Xa4(){return Zb;}()) + Ho(Lk0)](Cn, KGq, true)" fullword ascii
    $s17 = "   JBd[(function FIu0(){return DQw;}()) + TTo5]();" fullword ascii
    $s18 = "    Iq4[DHr](MZp0[BWl4 + Wy8 + Zw + (function Dx0(){return OYu;}())]);" fullword ascii
    $s19 = "    var Xp = GZn4[(function TAw(){return CZj;}()) + HUp + (function HYc2(){return XBy4;}()) + Ir(Rj3) + LPw](Rc, Xw);" fullword ascii
    $s20 = "   JBd = Sx[OEo + (function CSs(){return Zb;}()) + Lk0](Cn, BWb);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}