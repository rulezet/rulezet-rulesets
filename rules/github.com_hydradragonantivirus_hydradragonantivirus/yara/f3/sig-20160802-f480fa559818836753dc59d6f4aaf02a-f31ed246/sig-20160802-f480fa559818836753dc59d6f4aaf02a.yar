rule sig_20160802_f480fa559818836753dc59d6f4aaf02a {
  meta:
    description = "datamaliciousorder - file 20160802_f480fa559818836753dc59d6f4aaf02a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ba8e262bd7831f7a7efad55e9674870628aee0108560f7ade60661bb4e231b0"

  strings:
    $s1  = "    var aIv5 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "y(\\x29;\\x0d\\n\\tf\\x6f\\x72\\x20(var OPj=6938 - 6938;\\x20OPj \\x3c Tf\\x30[JQu(QSc) + (function \\x43n2(){return OX\\x769;}(" ascii
    $s3  = "a\\x72 UWy\\x34=Pe0[QSc + (function LBy(){r\\x65turn OXv9;}())];\\r\\n\\r\\nv\\x61\\x72\\x20GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Ya=" ascii
    $s4  = "\\x69\\x6fn Kx\\x32\\x28Ei\\x29{return Ei;};v\\x61r \\x53Uf2\\x20= \"http\" + \"\\x22;\\r\\nvar Lc = \"7\" \\x2b \\x22\";\\r\\nv" ascii
    $s5  = "\\n\\r\\nfunction KTb8 /* L  *\\x2f(\\x45\\x63)\\r\\n{\\r\\n    \\x76ar \\x57Hy0=WScript[\\x46w + (f\\x75ncti\\x6fn SSq(){return" ascii
    $s6  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s7  = "\\x717=ENo\\x3b}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7=Pa7\\x5bENo\\x5d;}\\r\\n\\t\\tDq\\x2epush(String[\\x43Wx0 + FXe1(\\x4ee6) " ascii
    $s8  = "\\x782(SUf2\\x29+(func\\x74ion Ry0(\\x29{return Og6;}())+\\x4eAm9+MSc5 + QRy5+RTo2(Lr8)+Un+WRr1 + Zx, S\\x55f2\\x2bQEw+MH\\x72" ascii
    $s9  = "\\n};\\r\\n\\r\\n\\r\\nfu\\x6ect\\x69on Ly(DHf1\\x20/* L  */)\\r\\n{\\r\\n  \\x20 va\\x72 Pa7=n\\x65w Array();\\r\\n\\t\\r\\nPa7" ascii
    $s10 = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s11 = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s12 = "'+''+' false);\\r\\n\\x09\\t\\tSy[Lr5]();\\x0d\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\t\\x69f (Sy.r\\x65ady\\x73tate\\x20< (-\\x31915 +" ascii
    $s13 = "(\\x58l2)+(function RGl2(){ret\\x75rn Gr4;}()) + (function I\\x69(){ret\\x75rn TEd;}(\\x29) + Zf+Hh+VUg + R\\x55f+Cp + IHt+(func" ascii
    $s14 = "2 + \"\";\\r\\nv\\x61r Vh = \"th\" \\x2b \\x22\";\\r\\nvar WKb = \"leng\"\\x20+ \"\\x22;\\r\\nfunction Su(SHv4\\x29{return SHv4" ascii
    $s15 = "v\\x61r \\x59Dx4 = \"t.\" \\x2b \"\";\\r\\nvar Rn =\\x20\"ip\" + \"\";\\r\\x0avar SW\\x62 = \"WScr\" + \"\";\\r\\nfunction\\x20U" ascii
    $s16 = "x20>>> 0) * 2.3283064365386963e-10;\\r\\n} else n = 0xef\\x638249d;\\r\\n};\\r\\n\\x72eturn mash;\\x0d\\n}\\r\\n\\r\\x0a\\x76ar " ascii
    $s17 = "5bQ\\x53c + OXv9];\\r\\x0a\\x76ar Pe0=(Dv3 + KJd + (function IMn()\\x7b\\x72et\\x75rn CZi8;}()), Zs5 + Te1\\x20+ Su(MSl) + Xt6);" ascii
    $s18 = "r\\nreturn\\x20Math.fl\\x6for(range * (rawpr\\x6e\\x67\\x28) + (\\x72awpr\\x6eg()\\x20* 0x200000 | 0) * 1.11022302\\x34625\\x315" ascii
    $s19 = "{\\r\\n\\t\\t\\tW\\x53cript[(function Ns5(){r\\x65tu\\x72\\x6e LJa;}\\x28))\\x5d(-1\\x3310 + 1410);\\r\\n\\t\\t\\tcontinue;\\r" ascii
    $s20 = "ipt[(function Wc\\x28)\\x7b\\x72etur\\x6e\\x20Fw\\x3b}()) + Mh + Yd6 \\x2b CYi + Up(DBs6\\x29](Pe[OPj])\\x3b\\r\\n\\t\\tbrea\\x6" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}