rule sig_20160722_fdecaf5938cda71913642934b8888869 {
  meta:
    description = "datamaliciousorder - file 20160722_fdecaf5938cda71913642934b8888869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a67a38d0537b7385e0c3de9e268eea17f3b894f03c78d76f6ee9cea59f02d057"

  strings:
    $s1  = "var Mx=WScript[NCc5(IYm) + (function Xq0(){return DVl;}()) + Ah + Pd4](Qs0 + TDd5 + (function Bx6(){return Hr1;}()) + Ey0);" fullword ascii
    $s2  = "    var Wc = WScript[IYm + DVl + (function Sn5(){return Ah;}()) + (function AAe6(){return Pd4;}())](Ga5 + XPw + (function NRv4()" ascii
    $s3  = "    var GJf = WScript[IYm + DVl + Ah + Pd4](En9 + BYs3 + (function Lm(){return Mp;}()) + (function Hr(){return Fb9;}()) + Kd + W" ascii
    $s4  = "    var GJf = WScript[IYm + DVl + Ah + Pd4](En9 + BYs3 + (function Lm(){return Mp;}()) + (function Hr(){return Fb9;}()) + Kd + W" ascii
    $s5  = "    var Jd = WScript[IYm + DVl + Ah + Pd4]((function YTf9(){return Nx8;}()) + Es + HYx8(CTg5) + XHd6 + IVr(Cy7) + KNf7);" fullword ascii
    $s6  = "    var Wc = WScript[IYm + DVl + (function Sn5(){return Ah;}()) + (function AAe6(){return Pd4;}())](Ga5 + XPw + (function NRv4()" ascii
    $s7  = "var LBs0=Ju + BAh + NWy + (function CUd2(){return ITn8;}());" fullword ascii
    $s8  = "function QMa7(Cu){return Cu;};var WYt = \"e\" + \"\";" fullword ascii
    $s9  = "{return FBx9;}()) + JHi);" fullword ascii
    $s10 = "function EJd(TSd){return TSd;};var PFy = \"e\" + \"\";" fullword ascii
    $s11 = "function ZGv(Dl){return Dl;};var Hs = \"e\" + \"\";" fullword ascii
    $s12 = "function HYx8(Dh5){return Dh5;};function IVr(Er4){return Er4;};var KNf7 = \"nt\" + \"\";" fullword ascii
    $s13 = "function NCc5(Jt){return Jt;};var Pd4 = \"t\" + \"\";" fullword ascii
    $s14 = "function Tb(OVw){return OVw;};var MJs = \"e\" + \"\";" fullword ascii
    $s15 = "function LEa2(Yo, RUq) {" fullword ascii
    $s16 = "function SCf4(Ej, RUq)" fullword ascii
    $s17 = "   DOw = Fl[(function SEk(){return XRo7;}()) + (function QWi6(){return OBx;}()) + CJd + Sl5](RUq, HKv8, true)" fullword ascii
    $s18 = "    Wc[(function Au5(){return It;}()) + UUr + PFy](CQc[BAn + ZGv(LMk) + OPy + (function Hg(){return EGc;}()) + (function We9(){r" ascii
    $s19 = "   Fl = new ActiveXObject(En9 + BYs3 + Mp + Fb9 + Kd + WBq + (function JOn(){return Wm5;}()))" fullword ascii
    $s20 = "    Wc[(function Au5(){return It;}()) + UUr + PFy](CQc[BAn + ZGv(LMk) + OPy + (function Hg(){return EGc;}()) + (function We9(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}