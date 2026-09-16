rule sig_20160722_7bbc766d2340648738eb146dfed7e1c0 {
  meta:
    description = "datamaliciousorder - file 20160722_7bbc766d2340648738eb146dfed7e1c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cb90e308315e39a708c40f54133f50b05473d3729edafb7b8a7b9ba7589f0cd"

  strings:
    $s1  = "var SZz8=WScript[(function Vl7(){return BFy;}()) + BYs0(NGb) + JZj9(Aa)](Xq + Rr + (function SRd(){return WFj2;}()) + Ix);" fullword ascii
    $s2  = "    var ZRb2 = WScript[(function Cv9(){return BFy;}()) + NGb + Aa](SJi6 + Nj + PRn9 + Go + (function Yg(){return Dj;}()) + Kb + " ascii
    $s3  = "    var Tc4 = WScript[STh9(BFy) + NGb + YNu5(Aa)](Ml1 + Eg(Pd6) + (function Ia(){return Mp;}()) + Vx + RYx);" fullword ascii
    $s4  = "    var ZRb2 = WScript[(function Cv9(){return BFy;}()) + NGb + Aa](SJi6 + Nj + PRn9 + Go + (function Yg(){return Dj;}()) + Kb + " ascii
    $s5  = "function Eg(Fy){return Fy;};var RYx = \"ent\" + \"\";" fullword ascii
    $s6  = "function BNr6(Fn){return Fn;};function Sz8(VRr2){return VRr2;};var Gw4 = \"ct\" + \"\";" fullword ascii
    $s7  = "function Dw(KMt1){return KMt1;};function YTw(PEy){return PEy;};var KZy6 = \"e\" + \"\";" fullword ascii
    $s8  = "function STh9(UVs6){return UVs6;};function YNu5(Ep){return Ep;};function BYs0(ABg){return ABg;};function JZj9(GIp0){return GIp0;" ascii
    $s9  = "function Rh0(TGe2){return TGe2;};var Nx = \"e\" + \"\";" fullword ascii
    $s10 = "function ZQq(Pd){return Pd;};var LRm = \"n\" + \"\";" fullword ascii
    $s11 = "function GPk7(Kv, AEc) {" fullword ascii
    $s12 = "function STh9(UVs6){return UVs6;};function YNu5(Ep){return Ep;};function BYs0(ABg){return ABg;};function JZj9(GIp0){return GIp0;" ascii
    $s13 = "function Hi(FXo5, AEc)" fullword ascii
    $s14 = "   Qz1 = Ir4[OBb + (function Vo9(){return Oe9;}()) + XRj5 + Nx](AEc, EYh7);" fullword ascii
    $s15 = "    Ra0[YYr](CQk4[Dw(Yc7) + (function Pr8(){return Gb;}()) + KPu + KTt + YTw(KZy6)]);" fullword ascii
    $s16 = "    var CQk4 = Tc4[RVp9 + YFw3 + Qa]((function Sd7(){return Dd;}()) + Nj0 + VKc3);" fullword ascii
    $s17 = "   Ir4 = new ActiveXObject(SJi6 + Nj + PRn9 + BNr6(Go) + Dj + Sz8(Kb) + Os + (function Nt6(){return Vm;}()) + Gw4)" fullword ascii
    $s18 = "   Qz1 = Ir4[OBb + Rh0(Oe9) + XRj5 + Nx](AEc, ZSk1, true)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}