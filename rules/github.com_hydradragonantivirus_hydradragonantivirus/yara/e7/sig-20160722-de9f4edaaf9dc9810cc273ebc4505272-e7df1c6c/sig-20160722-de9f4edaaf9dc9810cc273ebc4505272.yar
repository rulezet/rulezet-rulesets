rule sig_20160722_de9f4edaaf9dc9810cc273ebc4505272 {
  meta:
    description = "datamaliciousorder - file 20160722_de9f4edaaf9dc9810cc273ebc4505272.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "197895c115c20efdab330dd2e8ee62ca16cfbfcb3ddfce7aa9fe5729b82bea2a"

  strings:
    $s1  = "var GVa=WScript[Vn8 + EZl + Sy8(Sa1) + LJb5](HOc(CQc) + TIy + Jp4 + (function IPr(){return TOy9;}()));" fullword ascii
    $s2  = "    var Ai5 = WScript[Vn8 + EZl + PQp5(Sa1) + LJb5](AQw + Ir7 + WWi5 + Lh + (function PSw7(){return UCc;}()) + (function Cg(){re" ascii
    $s3  = "    var Ai5 = WScript[Vn8 + EZl + PQp5(Sa1) + LJb5](AQw + Ir7 + WWi5 + Lh + (function PSw7(){return UCc;}()) + (function Cg(){re" ascii
    $s4  = "function Jp(Wy){return Wy;};function QYl4(KEg2){return KEg2;};var AIn4 = \"te\" + \"\";" fullword ascii
    $s5  = "function De3(QJj5){return QJj5;};function PQp5(Av){return Av;};function Sy8(Fg1){return Fg1;};var LJb5 = \"ect\" + \"\";" fullword ascii
    $s6  = "function HOc(LBh){return LBh;};var TOy9 = \"ell\" + \"\";" fullword ascii
    $s7  = "function JDl(Lj){return Lj;};var GSw = \"n\" + \"\";" fullword ascii
    $s8  = "function CBm(Tr){return Tr;};var Yi7 = \"%/\" + \"\";" fullword ascii
    $s9  = "function Ce(Ew2){return Ew2;};var Mp3 = \"e\" + \"\";" fullword ascii
    $s10 = "function OAz6(ROp9){return ROp9;};var JHc3 = \"nt\" + \"\";" fullword ascii
    $s11 = "function Ra(JLb4){return JLb4;};var Hd8 = \"ine\" + \"\";" fullword ascii
    $s12 = "var v_binpath=Lf3+Vf7+(function Ps1(){return EGn5;}());" fullword ascii
    $s13 = "    YYo7[XYe6 + (function DMd(){return Lh0;}()) + ZGt6] = \"bin.base64\";" fullword ascii
    $s14 = "function DBx3(Un, Aa)" fullword ascii
    $s15 = "turn Xk;}()));" fullword ascii
    $s16 = "function Xr4(Ol, Aa) {" fullword ascii
    $s17 = "    GHe[GKr5 + Jp(AIn4)](YYo7[AUb7 + Ce(Ej8) + Kb0 + Fo6 + Zy7 + (function AUk(){return Mp3;}())]);" fullword ascii
    $s18 = "    var WJr5 = LBc[(function ZOp2(){return Ss;}()) + (function Sj8(){return SIi;}()) + HJi0 + Tq4 + Qf](Up3, VCe);" fullword ascii
    $s19 = "   GOk9 = new ActiveXObject(Sm + QTu + APx1 + Fs + (function Oq(){return Kt;}()) + ZWj + RQj9 + JEd6)" fullword ascii
    $s20 = "    var YYo7 = Ai5[(function WLm(){return Oi;}()) + Ez + Hi6 + OAz6(JHc3)](CBd1 + Bn4 + Oq9);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}