rule sig_20160802_46e2411fd210574665d83e8920d06270 {
  meta:
    description = "datamaliciousorder - file 20160802_46e2411fd210574665d83e8920d06270.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69d8f75ddfed7857321ee607aa04b6d1364b743f806481c372e3a69e5bfc0a14"

  strings:
    $s1  = "    var aZQa = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "urn OXv9;}())]; O\\x50j++)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\r\\n\\t\\tvar S\\x79=WScript[\\x28funct\\x69\\x6f\\x6e \\x57c(){return" ascii
    $s3  = " * s[p] + c * 2.32830643653869\\x363e-\\x310;\\r\\nreturn s[p] = t - (\\x63 =\\x20t | 0);\\r\\n}return random;}\\x28)\\x29;};\\r" ascii
    $s4  = "63 - 9\\x3731;\\r\\nPa7[255]=\\x316\\x30;\\r\\n\\x09\\r\\n\\tvar Dq=new Array();\\r\\n\\x09var Og=\"\";\\r\\n\\x09var ENo; var E" ascii
    $s5  = "\\x2b \"\";\\r\\nvar Un\\x20\\x3d \"md/mg\" + \\x22\";\\r\\nf\\x75nct\\x69on RT\\x6f2(Xh1){return X\\x681;}\\x3bvar Lr8 =\\x20\"" ascii
    $s6  = "\\x3dSq[EFq7]\\x3b}\\r\\x0a\\t\\tHFz[Mc0(L\\x6d) + (function Eo6()\\x7breturn Xe1;}()'+''+')](EN\\x6f);\\r\\n\\t};\\r\\n\\t\\r" ascii
    $s7  = "0;\\r\\n}\\r\\nreturn (n >>> 0) \\x2a 2.3283064365386963e-10;\\r\\n} else n = \\x30xefc8\\x3249d;\\r\\n}\\x3b\\r\\nre\\x74u\\x72" ascii
    $s8  = "z);\\r\\nv\\x61r RJp2\\x3dMz + Ok\\x20+ CLc9\\x20\\x2b T\\x63 +\\x20\\x53Mz9 +\\x20(function\\x20Lm9(){return TSx1;}());\\r\\n" ascii
    $s9  = "nvar YDx4 = \"t.\" + \"\";\\x0d\\n\\x76ar\\x20Rn = \"ip\" + \"\"\\x3b\\r\\nvar \\x53Wb = \"WScr\" + \"\";\\r\\n\\x66\\x75nct\\x6" ascii
    $s10 = "Yi + (\\x66\\x75nc\\x74ion PXo9(){return \\x44B\\x736;}())](Oe3+Vj+Vv+G\\x54g + XH\\x62\\x30 +\\x20Lu7);\\r\\x0a\\t\\tARt\\x5bRF" ascii
    $s11 = "3d \"l\\x6clll\" + \"\";\\r\\nfunction O\\x71(Pf0){return Pf0;};function SGv(KLy5){re\\x74urn KLy5;};fun\\x63tion JQu(KKh4){retu" ascii
    $s12 = "22e\\x6b.c\"\\x20+ \"\";\\r\\nfu\\x6ection GYe0(A\\x4ai\\x33){return AJi3;};var \\x5aWp \\x3d \"cn\" + \"\";\\r\\nvar GQ\\x634 =" ascii
    $s13 = "return Tl8;};var Xe1 = \"h\" + \\x22\";\\r\\nvar Lm = \"pus\"\\x20\\x2b\\x20\"\\x22;\\r\\nvar Rt =\\x20\"At\" +\\x20\"\";\\r\\n" ascii
    $s14 = "(Xl2)+(functio\\x6e RGl\\x32(){re\\x74urn Gr4;}()) \\x2b (function I\\x69(){return TEd;}\\x28)) +\\x20Zf\\x2bHh+VUg + \\x52\\x55" ascii
    $s15 = ";\\r\\nvar Ud8 = \"gt\" + \"\\x22'+''+';\\r\\nvar FOp3\\x20\\x3d \"len\" + \"\"\\x3b\\r\\nfunction Zb1(CZq){return CZq;};var Pa1" ascii
    $s16 = "r\\nva\\x72 CZy = \"ll\"\\x20+ \"\";\\r\\nvar Jl9 = \"lllll\" + \\x22\";\\r\\nfunction I\\x66(YB\\x65){return YBe;};var Kg = \"1" ascii
    $s17 = "var \\x56v = \"O\" + \\x22\"\\x3b\\r\\nf\\x75nction\\x20Vr\\x33(\\x50z8){return Pz8;};var Vj\\x20= \"D\" + \"\";\\r\\nvar Oe3 = " ascii
    $s18 = "nva\\x72 BSs4 = \"1123\" + \"\";\\x0d\\nvar Mz\\x39=\\x28BSs4 + If\\x28Kg), Jl9 + CZy \\x2b IIk2 +\\x20(function N\\x4by0(){\\x7" ascii
    $s19 = "t\\x09{EFq7=ENo\\x3b}\\r\\n\\t\\x09else\\x20\\r\\n\\t\\t\\x09{\\x45\\x46q7=Pa7[EN\\x6f];}\\r\\n\\t\\tDq.push(String[Hy8 + \\x49" ascii
    $s20 = "Vy(\\x4aGm3)]);\\r\\n\\t\\x09\\x41Rt[NAe0 + PJh\\x20+ MT\\x6a4]=1 \\x2a 0;\\r\\n\\t\\tARt[\\x28function AMj0(){return \\x4eh8;}(" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}