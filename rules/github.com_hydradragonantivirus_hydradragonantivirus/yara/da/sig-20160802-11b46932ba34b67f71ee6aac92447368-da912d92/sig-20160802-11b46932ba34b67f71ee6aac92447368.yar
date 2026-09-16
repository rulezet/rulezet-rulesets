rule sig_20160802_11b46932ba34b67f71ee6aac92447368 {
  meta:
    description = "datamaliciousorder - file 20160802_11b46932ba34b67f71ee6aac92447368.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "233d007f00afb4657a837af6ce4ef391cf5fdb852a5bda0f1581a8d7df39b67d"

  strings:
    $s1  = "    var aGJv = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "d\\nvar \\x42a5=WScript[DU\\x6d + Bb5 + (fu\\x6ection IJm(){ret\\x75rn I\\x4ah;\\x7d()) + Fl2\\x5d\\x28(function RGn()\\x7b\\x72" ascii
    $s3  = "ion N\\x735(){return LJa;}())]\\x28-\\x313\\x310 + 1410);\\r\\x0a\\t\\t\\tcontinu\\x65;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\x09\\t" ascii
    $s4  = "+'WScript[LJ\\x61](1000);\\r\\n\\t\\t\\x09}\\r\\n\\t\\t\\tSy[Pc0\\x5d(LEs7, \\x45Rb[\\x4fEq6+\\x2b % E\\x52b[QSc + O\\x58v\\x39]" ascii
    $s5  = ");\\x20continue\\x3b};\\x0d\\n} while (Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\nfunc\\x74ion BKw(DHf1\\x20/* L  */)\\r\\n{\\r" ascii
    $s6  = "2.3\\x32830\\x364365386963e\\x2d10;\\r\\x0areturn s[p] = t - (c =\\x20t | 0);\\r\\n}return rando\\x6d;}());};\\r\\n\\r\\nfunctio" ascii
    $s7  = "r\\x20UWy4\\x3dPe0[QSc + (function LBy(){re\\x74urn OXv9;}())];\\r\\n\\r\\nva\\x72\\x20\\x47Rx5=1;\\r\\nvar DAe=2;\\r\\nvar Ya=3" ascii
    $s8  = " \\x42b5 \\x2b IJh + (func\\x74ion SSq(){return Fl2;}())](MVd1(Qg)+Wt6+Fu3+RDj + PIs6 \\x2b Wz3);\\r\\n\\t\\tARt[Pc\\x30]();\\r" ascii
    $s9  = "221123\" + \"\\x22;\\x0d\\nvar \\x4dz9=(BSs4 + If(Kg\\x29, Jl9\\x20+ CZy + II\\x6b2\\x20+ \\x28function NKy0(){return EYf;}()\\x" ascii
    $s10 = "2){return L\\x72;\\x7d;fu\\x6ection \\x58p6\\x28I\\x6b){return Ik;};var Fu3 =\\x20\"O\" + \"\";\\r\\nfunction Vw3\\x28NAa){retur" ascii
    $s11 = "\";\\r\\nfunction ORk1(Ds){return\\x20Ds;};\\x76ar Xz4 = \"se\"\\x20+ \"\";\\r\\nvar Pg3\\x20= \"clo\" + \"\";\\r\\nf\\x75nctio" ascii
    $s12 = "Nh + JZe + Sk\\x20+ Wi2 + (function BIy1(){return INw6;\\x7d()) +\\x20Wk9 + E\\x731, N\\x49p\\x20+ XAi3 + Ic0 + Y\\x763\\x5d;\\r" ascii
    $s13 = "]== 0x5a)\\r\\n\\t\\t{re\\x74u\\x72\\x6e true;}\\r\\n\\t\\x65lse\\x0d\\n\\t\\t{return f\\x61lse;}\\r\\x0a};\\r\\n\\x0d\\n\\r\\nf" ascii
    $s14 = "r\\nvar RJp2=Mz +\\x20GOk + CLc9 + Tc + SMz9;\\r\\nvar RCn=RJp2 + (function L\\x6d9\\x28){r\\x65turn\\x20Jp8;}()) + APr1\\x3b\\r" ascii
    $s15 = "\"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nfu\\x6ection Nq(O\\x42j){return O\\x42j;\\x7d;functi\\x6fn\\x20ETx9(ZZc8){ret" ascii
    $s16 = "J\\x49a + (function Ew(){retur\\x6e Vs;}()) + Yy1+Hq1+TNk4(T\\x58y)+(fu\\x6ection RGl\\x32(){return Gr4;}()\\x29 + (function Ii(" ascii
    $s17 = "x72eturn TEd;}())\\x20+ Zf+Hh+VUg + RUf+Cp + \\x49Ht+(\\x66unction W\\x636(){return HPu9;}())+(function Mh(){return Re1;}\\x28))" ascii
    $s18 = "(functi\\x6fn Cn2(){return OXv9;}())]; OPj++)\\x0d\\n\\t{\\r\\n\\t\\t\\x76\\x61r EFq7=Tf0[SMe3 + Ec\\x39 \\x2b\\x20Ka](OPj);\\r" ascii
    $s19 = "1S\\x63 + OXv9];\\r\\n\\x76\\x61r Pe0=(Dv3 + KJd + (function IMn(){\\x72\\x65tu\\x72n CZi8;}()), Zs5 + Te1 \\x2b Su(MSl) + Xt6);" ascii
    $s20 = "Er8;};functio\\x6e RV\\x79(Mb0){return Mb0;};v\\x61r\\x20Z\\x56t7\\x20= \"le\\x22 + \"\\x22;\\r\\nvar LWr\\x20= \"oFi\" + \"\";" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}