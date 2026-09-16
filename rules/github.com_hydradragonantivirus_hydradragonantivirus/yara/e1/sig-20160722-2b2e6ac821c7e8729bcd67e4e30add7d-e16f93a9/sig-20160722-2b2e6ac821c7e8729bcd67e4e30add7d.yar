rule sig_20160722_2b2e6ac821c7e8729bcd67e4e30add7d {
  meta:
    description = "datamaliciousorder - file 20160722_2b2e6ac821c7e8729bcd67e4e30add7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c14e9a00e518496f8d2a28e550a897be2315a4d9afd7df191b3010100bc6729c"

  strings:
    $s1  = "var SVd8=WScript[VAq1 + VJx9 + NDc2 + Kl0 + Sj7(RWs1)](Kr4(BJr) + (function VZf(){return VWb;}()) + GWz9 + MFd0);" fullword ascii
    $s2  = "function FPi(Ny){return Ny;};var XTe0 = \"Run\" + \"\";" fullword ascii
    $s3  = "    var Df7 = WScript[VAq1 + Nu(VJx9) + (function Zt(){return NDc2;}()) + Kl0 + RWs1](QNr + MHf(MNj) + AWc + Vg + Jv + TWx + Mw)" ascii
    $s4  = "    var FYq = WScript[UFh1(VAq1) + (function Gz4(){return VJx9;}()) + Lm(NDc2) + Kl0 + RWs1](APp5(Iw) + (function Cd(){return OC" ascii
    $s5  = "    var Df7 = WScript[VAq1 + Nu(VJx9) + (function Zt(){return NDc2;}()) + Kl0 + RWs1](QNr + MHf(MNj) + AWc + Vg + Jv + TWx + Mw)" ascii
    $s6  = "function EGw1(LXe5){return LXe5;};function BMi0(Va8){return Va8;};function Ey(Mk){return Mk;};var Fb = \"e\" + \"\";" fullword ascii
    $s7  = "var OJs=EDo + (function Ti(){return Nk7;}()) + RLz;" fullword ascii
    $s8  = "function Lb0(Xu){return Xu;};var Eh8 = \"e\" + \"\";" fullword ascii
    $s9  = "function Kr4(We9){return We9;};var MFd0 = \"ll\" + \"\";" fullword ascii
    $s10 = "function Fi(Cb4){return Cb4;};function Vw(Bt){return Bt;};var UWd1 = \"e\" + \"\";" fullword ascii
    $s11 = "var RNb9=OJs + (function BEb3(){return Cm;}()) + Pq5;" fullword ascii
    $s12 = "function Cu(GHz0){return GHz0;};function Bn8(Xa){return Xa;};var XAw = \"nt\" + \"\";" fullword ascii
    $s13 = "function No4(IVj7){return IVj7;};var ZKa9 = \"ype\" + \"\";" fullword ascii
    $s14 = "function Nu(Nb5){return Nb5;};function UFh1(YLj3){return YLj3;};function Lm(Te){return Te;};function Sj7(Zt7){return Zt7;};var R" ascii
    $s15 = "function MVy1(HFc){return HFc;};var XPg1 = \"e\" + \"\";" fullword ascii
    $s16 = "function Hf8(YXi){return YXi;};var WOg = \"ment\" + \"\";" fullword ascii
    $s17 = "function Wn(NOs0){return NOs0;};var HHg = \"Type\" + \"\";" fullword ascii
    $s18 = "function UWz7(Cb){return Cb;};var JSe1 = \"dLine\" + \"\";" fullword ascii
    $s19 = "function TUn(JCp1){return JCp1;};var Ac = \"en\" + \"\";" fullword ascii
    $s20 = "function APp5(Nh){return Nh;};var NIx0 = \"eam\" + \"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}