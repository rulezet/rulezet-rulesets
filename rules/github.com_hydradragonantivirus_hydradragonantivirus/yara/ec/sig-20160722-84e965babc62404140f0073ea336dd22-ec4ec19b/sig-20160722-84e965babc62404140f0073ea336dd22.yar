rule sig_20160722_84e965babc62404140f0073ea336dd22 {
  meta:
    description = "datamaliciousorder - file 20160722_84e965babc62404140f0073ea336dd22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e32d9ecb83b47f5e0f259cd6d60e629cd592cc16274667f650c755d700525aa"

  strings:
    $s1  = "var Fa7=WScript[(function Rc2(){return Bf;}()) + Lq + ZWq3](VOr7 + Bs(LVy) + QTl1(Ga) + FBv3);" fullword ascii
    $s2  = "function Bs(Py){return Py;};function QTl1(Xt){return Xt;};var FBv3 = \"Shell\" + \"\";" fullword ascii
    $s3  = "function GAq1(XBw6){return XBw6;};var Wy2 = \"Run\" + \"\";" fullword ascii
    $s4  = "function DOd(WRc5){return WRc5;};var Co = \"ta\" + \"\";" fullword ascii
    $s5  = "    var KUl5 = WScript[Bf + Lq + ZWq3](Sn9 + ANt(Tf6) + Xo8 + DVv + XMj7 + GKs5 + (function Om4(){return QBe;}()) + JKz7);" fullword ascii
    $s6  = "    var JEq4 = WScript[Bf + Lq + ZWq3](RMb + Lq5 + Uc9(Yc0) + (function Qq(){return Lx;}()) + Vq3 + OSm + Zy(YUa));" fullword ascii
    $s7  = "Fa7[GAq1(Wy2)](GNo6 + (function VVj(){return Op9;}()));" fullword ascii
    $s8  = "function Fm5(Vw){return Vw;};var Dr2 = \"pe\" + \"\";" fullword ascii
    $s9  = "function Uc9(Xw5){return Xw5;};function Zy(Qg7){return Qg7;};var YUa = \"t\" + \"\";" fullword ascii
    $s10 = "function ANt(MRl){return MRl;};function Xy(MRu){return MRu;};var JKz7 = \"ect\" + \"\";" fullword ascii
    $s11 = "var Id=MVj + (function ODp3(){return Xj1;}()) + PUh5 + (function UJg(){return JQq6;}());" fullword ascii
    $s12 = "function Gl0(Bp6){return Bp6;};function PMu(NIv){return NIv;};function NBh(Yt5){return Yt5;};var Ih4 = \"le\" + \"\";" fullword ascii
    $s13 = "function ZMw5(NOf){return NOf;};var Pd3 = \"xe\" + \"\";" fullword ascii
    $s14 = "function Hn(Nq7){return Nq7;};var Sn90 = \"nt\" + \"\";" fullword ascii
    $s15 = "function CGb(Pb3){return Pb3;};var IAn = \"eam\" + \"\";" fullword ascii
    $s16 = "    XYu6[Yj2 + (function Fp(){return SPn7;}()) + Fm5(Dr2)] = \"bin.base64\";" fullword ascii
    $s17 = "    var LYd = WScript[Bf + Lq + ZWq3](XRb6 + XCa1 + GVy3 + SXe7 + (function EZh(){return Oi;}()));" fullword ascii
    $s18 = "function Jp(Je0, ACo5)" fullword ascii
    $s19 = "function Hj(COy, ACo5) {" fullword ascii
    $s20 = "    XYu6[SBc8] = Cl[(function AOm2(){return Iy6;}()) + OGl]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}