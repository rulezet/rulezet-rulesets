rule sig_20160802_0d0e27b1aa699f85f87228792a90742f {
  meta:
    description = "datamaliciousorder - file 20160802_0d0e27b1aa699f85f87228792a90742f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24a4ac354229c788926d42aa266654f4b2d3fbc15f0e775159a34324dadc033d"

  strings:
    $s1  = "    var aNw = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "())+(fun\\x63tion Mh(){return Re1;}(\\x29)];\\r\\nvar Ba5=WScript[DUm + Bb5 + (function IJm(){re\\x74u\\x72n I\\x4ah;}(\\x29) + " ascii
    $s3  = "253]=178;\\x0d\\n\\x50a7[\\x3254]=19363 - 9731;\\r\\nPa7[2\\x355]=160;\\r\\n\\t\\r\\n\\x09var Dq=new Array();\\r\\n\\tv\\x61r Og" ascii
    $s4  = " Hg0(\\x59j0)](Qg(Oi0), ERb[OEq6++ % ERb[QSc + OXv9]], false);\\r\\n\\t\\x09\\tSy[TTv(HXb)]();\\x0d\\n\\t\\t}\\r\\n\\t\\t\\r\\n" ascii
    $s5  = "\\x20+ Ft\\x20+ Pz);\\r\\nvar RJp2=Mz\\x20+ Bz + LIz + Tc + S\\x4dz9\\x20+ (function Lm9(\\x29{return\\x20TSx1;\\x7d());\\r\\nva" ascii
    $s6  = "\\nvar \\x55\\x4dc=\"437\"\\x3b\\r\\n\\r\\nvar ERb=[SUf2+Kx2 + \\x28function Fb(){return Ei;}\\x28))+Qc4\\x2b(function\\x20Zq9()" ascii
    $s7  = "var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s8  = "\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){ret" ascii
    $s9  = " = \"gt\" + \"\";\\r\\nvar FOp3 = \"\\x6c'+''+'en\" + \"\";\\r\\n\\x66\\x75nction Zb1(\\x43Zq){return CZq;};var Pa1 = \"l\" + \"" ascii
    $s10 = "9];\\r\\nvar Pe0=(Dv\\x33 + K\\x4ad + (\\x66unctio\\x6e IMn(){return CZi8;}'+''+'\\x28)), Zs5 + Te1 + Su(MSl) + Xt6\\x29;\\x0d" ascii
    $s11 = "var random = funct\\x69on(\\x20range ) {\\r\\n\\x72etur\\x6e Math.floor(range * (r\\x61wprng() + (rawprng() *\\x200x200000 | 0) " ascii
    $s12 = "t\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){return" ascii
    $s13 = "(Yz) +\\x20Es1, Pm + RKw + COs7 + Ru +\\x20Sp];\\r\\n\\r\\nf\\x6fr (va\\x72\\x20\\x4fP\\x6a=0; OPj < Pe[QSc + (function F\\x54j(" ascii
    $s14 = "n\\t\\t\\tcontinue;\\r\\x0a\\t\\x09}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WS\\x63ript[D\\x55\\x6d +\\x20Bb5 + \\x49Jh + \\x28fu\\x6ect" ascii
    $s15 = "t\\t'+''+'{\\r\\n\\t\\t\\tVg8(RCn, HFz\\x29;\\r\\n\\t\\t} \\r\\x0a\\t\\t\\x63atch (e) {break;};\\t\\t\\r\\n\\t\\t\\r\\n\\x09\\tB" ascii
    $s16 = "3\" \\x2b \"\";\\r\\nvar Mz9=(BSs4 \\x2b If(Kg)\\x2c \\x4al9 + CZy \\x2b IIk2 + (functi\\x6fn NKy0(\\x29{return EYf\\x3b}()))\\x" ascii
    $s17 = "s3 + (function O\\x79(\\x29{return AX\\x796;}()) + Rt](OPj);\\x0d\\n\\t\\tif\\x20(EFq7 < (4 *\\x20\\x332))\\r\\n\\t\\t\\t{\\x76a" ascii
    $s18 = "b}\\r\\n\\t\\telse\\r\\n\\x09\\t\\t{var ENo=Sq[EFq7]\\x3b}\\r\\n\\t\\tHFz[Mc0(L'+''+'m) + \\x28function Eo6(){return Xe1;}()\\x2" ascii
    $s19 = "tARt[Ub\\x5d\\x28Sy[ZWl + (fun\\x63tion\\x20Er8()\\x7breturn RMs4\\x3b}()) + VJk5 + RVy(JGm3)\\x5d);\\r\\n\\t\\t\\x41Rt[NAe0 + P" ascii
    $s20 = "\" + \"\\x22;\\r\\nvar Jl9 \\x3d \"lllll\" + \"\";\\r\\nfunction If\\x28YBe){return YB\\x65;};\\x76ar Kg = \"132\" + \"\";\\r\\n" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}