rule sig_20160802_d4e0618907e014e03c288d74392c4c0c {
  meta:
    description = "datamaliciousorder - file 20160802_d4e0618907e014e03c288d74392c4c0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7072d333377446cc54fbd9ff8988aa3742524519ad7b69cb042a864d3b6779dd"

  strings:
    $x1  = "    var aGFm = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = " Ns5(){return LJa;\\x7d(\\x29)\\x5d(-1310 + 14\\x310);\\r\\n\\t\\t\\tco\\x6etinue;\\r\\n\\t\\t}\\r\\x0a\\t\\x09\\r\\n\\t\\tvar A" ascii
    $s3  = "3963e\\x2d10;\\r\\nreturn\\x20s[p]\\x20= t - (c = t | 0);\\r\\n}r\\x65turn random;}());};\\r\\n\\r\\x0afunction Mash() {\\r\\nva" ascii
    $s4  = "6Td]\\x28RCn + \\x48Iy6);\\r\\n\\t\\t\\x62reak;\\r\\n\\t\\x7d\\r\\n\\tcatch (e) {WScript[LJ\\x61](1000); continue;};\\r\\n} whil" ascii
    $s5  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s6  = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s7  = "ML\" \\x2b \"\";\\r\\nvar Sy8 = \"ML\" + \"\";\\r\\nvar IFc4 = \"\\x4d\\x53X\"\\x20+ \"\";\\r\\x0afunction QKv(Dq8){return Dq8;}" ascii
    $s8  = "{return K\\x48z9;};var Nt0 = \"\\x35.1\" +\\x20\"\";\\r\\nvar YWl7 = \"t.\" + \"\";\\r\\n\\x76ar Ki5 \\x3d \\x22ques\" + \"\";" ascii
    $s9  = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s10 = "0Sg7 + Lm + H\\x78](MVd1(Qg)+Wt6+Fu3+RDj + PIs6 + Wz3);\\r\\n\\t\\tARt[Pc0]();\\r\\n\\t\\x09ARt[(function Cb\\x28){return TGa9;}" ascii
    $s11 = "Mz + Qs \\x2b (function Pj2(){return GOk;}()) + CLc9;\\r\\nvar RCn=R\\x4ap\\x32 + \\x4dw7 +\\x20FUy;\\r\\n\\r\\nfunctio\\x6e uhe" ascii
    $s12 = "IKv+Aq + \\x48Jj9+Qu+Wb4, MSc5 + QRy5\\x2b(fun\\x63tion RGl2\\x28){return Bg2;}())+Ii + QMf2+Ug + RUf+(function I\\x48t(){\\x72e" ascii
    $s13 = " IIk2\\x20= \"VV\" + \"\";\\r\\nvar CZy = \"VV\" + \"\";\\r\\nvar \\x4al9 = \"VVVVV\" +\\x20\"\";\\r\\nfunction If(YBe){return Y" ascii
    $s14 = "()\\x29+Qc4+(\\x66unction \\x5aq9(){return Nl;}(\\x29)+Wn1+RWi+Po+Cy5 + Nn5+(function GNn(){re\\x74ur\\x6e FYs1;\\x7d\\x28))+Rj3" ascii
    $s15 = "3869\\x363\\x65-\\x310;\\r\\x0a} else n = 0xefc\\x382\\x349\\x64;\\r\\n};\\r\\nreturn mash;\\x0d\\n}\\r\\n\\r\\nvar \\x50e=[Lf7 " ascii
    $s16 = "Gz = 67\\x32\\x3168;\\r\\nvar Id=NVd[QSc + OXv9];\\r\\nvar P\\x65\\x30=(\\x44v3 + KJd + (function IM\\x6e(){return CZi8;}())\\x2" ascii
    $s17 = "x22\\x20+ \\x22\";\\r\\nvar Ud\\x38 = \"gt\" + \\x22\";\\r\\n\\x76ar FOp3 = \"len\"\\x20+ \"\";\\r\\nfun\\x63\\x74ion Zb1(C\\x5a" ascii
    $s18 = "c\\x74i\\x6fn Bb5(IJh){re\\x74urn IJh;};f\\x75nction Up(Wr6){return W\\x726;};var Hx = \"ct\" + \"\";\\r\\nvar Lm = \"Obje\" + " ascii
    $s19 = "1\\x332\\x22 + \"\"\\x3b\\r\\nvar BSs4 = \"11\\x323\" + \\x22\";\\r\\nvar Mz\\x39=\\x28BS\\x734 + If(Kg), Jl9 + CZy + IIk2 +\\x2" ascii
    $s20 = "\\r\\nfunction VO\\x797(DHf1 /\\x2a L\\x20 */)\\r\\n{\\x0d\\n\\x09if \\x28DHf1[0]== 0x4D && DHf1[1]== 0x5a)\\r\\n\\t\\t{return t" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}