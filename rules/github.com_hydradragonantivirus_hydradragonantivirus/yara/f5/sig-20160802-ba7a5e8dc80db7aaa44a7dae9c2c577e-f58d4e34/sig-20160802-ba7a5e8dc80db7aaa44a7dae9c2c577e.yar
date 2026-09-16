rule sig_20160802_ba7a5e8dc80db7aaa44a7dae9c2c577e {
  meta:
    description = "datamaliciousorder - file 20160802_ba7a5e8dc80db7aaa44a7dae9c2c577e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e1b5f9baeb324b0db146cdcfcd772ccada7e845d560419826745a13b89528c8"

  strings:
    $s1  = "    var aQh9 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "a\\x72 Ba5=WScript[\\x44Um + Bb5 + (\\x66unction IJm(){r\\x65turn\\x20IJ\\x68;}()) + F\\x6c\\x32]((function RGn\\x28\\x29{return" ascii
    $s3  = "Script[\\x4cJa](1000);\\r\\n\\x09\\t\\t}\\r\\n\\t\\t\\tSy[P\\x630](LEs7\\x2c ER\\x62[OEq\\x36++ %\\x20ERb[QSc +\\x20O\\x58v9]], " ascii
    $s4  = "20Ns5(){return LJa;}()\\x29]\\x28-\\x31310 + 1410)\\x3b\\r\\n\\t\\t\\tconti\\x6eue;\\r\\n\\t\\t}\\r\\n\\t\\t\\x0d\\n\\x09\\tvar " ascii
    $s5  = "in\\x75e;\\x7d;\\r\\n} while (Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\nfu\\x6ection BKw(DH\\x661 /* L  */)\\r\\n\\x7b\\r\\n" ascii
    $s6  = "u\\x6ection LBy(){return OXv9;}())\\x5d;\\r\\n\\r\\nvar GRx5=1;\\r\\nvar\\x20\\x44\\x41e=2;\\r\\nvar Ya=3607 - 3605;\\r\\nvar UM" ascii
    $s7  = "x2e328\\x3306436538696\\x33e-10\\x3b\\r\\nreturn s[p] = t - (c\\x20= t | 0);\\r\\n}return ran\\x64om;}());};\\r\\n\\r\\nfunction" ascii
    $s8  = "Sq=n\\x65w Array();\\r\\n\\t\\r\\nSq[2071 -\\x201872'+''+']\\x3d128;\\r\\nSq\\x5b252]=129;\\x0d\\nSq[233]=13\\x30;\\x0d\\nSq[226" ascii
    $s9  = "2){return L\\x72;\\x7d;fu\\x6ection \\x58p6\\x28I\\x6b){return Ik;};var Fu3 =\\x20\"O\" + \"\";\\r\\nfunction Vw3\\x28NAa){retur" ascii
    $s10 = "\";\\r\\nfunction ORk1(Ds){return\\x20Ds;};\\x76ar Xz4 = \"se\"\\x20+ \"\";\\r\\nvar Pg3\\x20= \"clo\" + \"\";\\r\\nf\\x75nctio" ascii
    $s11 = "\"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nfu\\x6ection Nq(O\\x42j){return O\\x42j;\\x7d;functi\\x6fn\\x20ETx9(ZZc8){ret" ascii
    $s12 = "Er8;};functio\\x6e RV\\x79(Mb0){return Mb0;};v\\x61r\\x20Z\\x56t7\\x20= \"le\\x22 + \"\\x22;\\r\\nvar LWr\\x20= \"oFi\" + \"\";" ascii
    $s13 = " Pe0=(Dv3 +\\x20\\x4bJd + (function IMn(){return CZi8;}(\\x29\\x29, \\x5as5 + Te1 + Su(MSl) + Xt\\x36);\\r\\nvar UWy4=Pe0[QS\\x6" ascii
    $s14 = "h\" + \\x22\";\\r\\nvar WKb \\x3d \\x22leng\" + \"\";\\r\\nfunctio\\x6e Su\\x28SHv4){return SHv4;}\\x3bvar Xt6 = \"l\\x6c\\x22 +" ascii
    $s15 = "c\\x74ion Cn2(){return OXv9;}())]; OPj+\\x2b)\\r\\n\\t{\\r\\n\\x09\\x09var EFq7=Tf0[SMe3 + \\x45c\\x39\\x20+ Ka](OPj);\\r\\x0a" ascii
    $s16 = "nvar Jl9 =\\x20\"lllll\" + \"\";\\r\\nfunction If(YBe){return Y\\x42e;};var Kg = \"\\x3132\" + \"\";\\r\\nvar BSs4 = \"1123\" +" ascii
    $s17 = "+ JZe + \\x53k + Wi2 + (function BIy1(){return INw\\x36;}())\\x20+ Wk9 +\\x20Es1,\\x20N\\x49p + XAi3 + Ic0 +\\x20Y\\x763];\\r\\n" ascii
    $s18 = ")\\r\\n\\t\\t{\\x72e\\x74\\x75rn true;}\\r\\x0a\\tel\\x73e\\r\\n\\t\\t{return\\x20false;\\x7d\\r\\n};\\x0d\\n\\r\\n\\r\\nfunctio" ascii
    $s19 = ")\\r\\n\\t{\\r\\n\\t\\tREt2=\\x28REt2 + DH\\x661[OPj]) % 0x1000\\x300000;\\x0d\\n\\t};\\r\\n\\tif (RE\\x742 != Cm) {return [];};" ascii
    $s20 = "){return Z\\x66;}())+Mf2+VUg + RUf+Cp \\x2b IHt\\x2b(function\\x20Wc6(){return HPu9;}())+(function Mh(){return Re1\\x3b}())\\x5d" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}