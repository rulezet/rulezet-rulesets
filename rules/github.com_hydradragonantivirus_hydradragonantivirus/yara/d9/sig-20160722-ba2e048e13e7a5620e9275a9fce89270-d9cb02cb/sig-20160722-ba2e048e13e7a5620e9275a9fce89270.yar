rule sig_20160722_ba2e048e13e7a5620e9275a9fce89270 {
  meta:
    description = "datamaliciousorder - file 20160722_ba2e048e13e7a5620e9275a9fce89270.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b68990362277e5f2ce52ded7ea6c60984929e65d260a6310fbb48c438b16a11"

  strings:
    $s1  = "var LPb=WScript[HYo + BYj(Qx) + YXt3 + COh](Wk + PSi5 + So0(Jo) + (function Wx(){return Fn3;}()) + DJf(Om3));" fullword ascii
    $s2  = "    var LCh = WScript[(function IHz0(){return HYo;}()) + Qx + YXt3 + COh](Ov5 + Dy6 + Ro8 + Qq4(Da));" fullword ascii
    $s3  = "    var WUa = WScript[HYo + (function VQi2(){return Qx;}()) + (function CWu8(){return YXt3;}()) + CGn9(COh)]((function Wp2(){ret" ascii
    $s4  = "    var WUa = WScript[HYo + (function VQi2(){return Qx;}()) + (function CWu8(){return YXt3;}()) + CGn9(COh)]((function Wp2(){ret" ascii
    $s5  = "function Qq4(Ab){return Ab;};var Da = \"eam\" + \"\";" fullword ascii
    $s6  = "function CGn9(RTg){return RTg;};function GCs(NIz2){return NIz2;};function Qs3(Dw8){return Dw8;};function BYj(VJq1){return VJq1;}" ascii
    $s7  = "function Fo9(Cw){return Cw;};var SPb7 = \"e\" + \"\";" fullword ascii
    $s8  = "function FNv(WAx){return WAx;};var BEu2 = \"e\" + \"\";" fullword ascii
    $s9  = "function YLl7(UBe4){return UBe4;};var Vm = \"ite\" + \"\";" fullword ascii
    $s10 = "urn Ys;}()) + PAg7 + YCg9 + Kx + Fe5 + Fp(Yx) + (function KId(){return HFr;}()) + Zv);" fullword ascii
    $s11 = "function Mq8(Qh){return Qh;};function MPh5(Wc8){return Wc8;};var ZXm = \"nt\" + \"\";" fullword ascii
    $s12 = "function Ut8(CGx5){return CGx5;};var FLb = \"en\" + \"\";" fullword ascii
    $s13 = "function Eb(Dr){return Dr;};var Ae = \"t\" + \"\";" fullword ascii
    $s14 = "function Fp(Bz5){return Bz5;};var Zv = \"bject\" + \"\";" fullword ascii
    $s15 = "function So0(ZVr){return ZVr;};function DJf(GLj1){return GLj1;};var Om3 = \"l\" + \"\";" fullword ascii
    $s16 = "function VGq3(Qf, QLw)" fullword ascii
    $s17 = "function Yn(Gy, QLw) {" fullword ascii
    $s18 = "function CGn9(RTg){return RTg;};function GCs(NIz2){return NIz2;};function Qs3(Dw8){return Dw8;};function BYj(VJq1){return VJq1;}" ascii
    $s19 = "   AUb = new ActiveXObject(Ys + PAg7 + (function Pr7(){return YCg9;}()) + Kx + Fe5 + Yx + HFr + (function Hg6(){return Zv;}()))" fullword ascii
    $s20 = "    var Lk = Rr[Qv + (function Pp(){return TLb;}()) + Ak + (function Bi8(){return Vq;}()) + SPt7](Hp, Ov3);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}