rule sig_20160802_e152769d7cd09c794e732e9ccc64b25c {
  meta:
    description = "datamaliciousorder - file 20160802_e152769d7cd09c794e732e9ccc64b25c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a09745d34fb466e6f31559852f1d9924640e188d681a99298b4bf7b1f684af5c"

  strings:
    $s1  = "    var aCp = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "\\r\\n\\t\\tvar\\x20ARt=WScript[(function CYi(){return Ci2;}()) + (function\\x20ELr4(){return Oj\\x36;}()) + IVm + Yk]\\x28TYj+M" ascii
    $s3  = "72 Qq = \"//rs\\x22 + \"\"\\x3b\\r\\nv\\x61r WSb\\x30 = \"p:\" + \"\";\\r\\n\\x66unc\\x74ion Rj3(T\\x58h){return T\\x58h;};var S" ascii
    $s4  = "())+O\\x6a2+Xs5 + Lq3+Wc+(functio\\x6e AXa\\x28){return \\x4eLs;}())];\\r\\nvar Ba5=WScript[Je4(Ci2) + KQd9(Oj6) \\x2b FJq\\x28I" ascii
    $s5  = " \\x74 - (c = t |\\x200);\\r\\x0a}return random;}());};\\x0d\\n\\r\\nfunction Mash() {\\r\\n\\x76ar n = 0xefc8249d;\\r\\nvar mas" ascii
    $s6  = " (var OPj=6\\x3938 - \\x36938\\x3b OPj\\x20< \\x54f0[JQu(QSc) + (\\x66u\\x6ection \\x43n\\x32(){return OXv9;}\\x28))\\x5d; OPj++" ascii
    $s7  = "[25\\x34]=1\\x39363 - 97\\x331;\\r\\nPa7[255]\\x3d160;\\r\\n\\t\\r\\n\\tv\\x61r Dq=n\\x65w Array();\\r\\n\\t\\x76ar Og=\"\";\\r" ascii
    $s8  = "x09el\\x73\\x65\\r\\n\\t\\t\\t{\\x76ar ENo=S\\x71\\x5bEFq7];}\\r\\n\\t\\tHFz[(function Gk(){return RUn9;}()\\x29 + JVi](\\x45No)" ascii
    $s9  = "\\x20Xx4 + NId1, (function Dq8(){return NC\\x61;}())\\x20+ Zk(Ze\\x29 + S\\x6b \\x2b (function BIy1(\\x29{\\x72eturn Wi2;}())];" ascii
    $s10 = "n\\x66\\x6fr (v\\x61\\x72 O\\x50j=0; OPj < Pe[QS\\x63 + (function F\\x54j(){return\\x20OXv9;}()\\x29]; \\x4f\\x50j++)\\r\\n\\x7b" ascii
    $s11 = "(function Ry0(){r\\x65turn Qq;}())+NAm9+MSc5 + \\x51Ry5+RT\\x6f2(Lr8)+Un\\x2c Cl8+Ae+Yy1 + Ri5\\x2b(function Xl2(){r\\x65\\x74ur" ascii
    $s12 = "22\";\\r\\nvar Ep3 \\x3d \\x2243\" + \"\";\\r\\nvar Vh = \\x22th\"\\x20+ \"\";\\r\\nvar WKb = \"l\\x65ng\" + \"\";\\r\\nf\\x75" ascii
    $s13 = "216\\x38\\x3b\\r\\nvar Id=NVd[QSc + OXv9];\\r\\nvar Pe0=\\x28\\x44v3\\x20+ KJd + (function IMn()\\x7breturn CZi8;}()), Z\\x735" ascii
    $s14 = "634+(fun\\x63tion Zq9\\x28){return Nl;}())+\\x57n1+RWi+Po+Cy5 + Nn5+(function GNn(){retur\\x6e F\\x59s1;}()\\x29\\x2c Rj3(Sj\\x3" ascii
    $s15 = "false);\\r\\x0a\\t\\t\\x09\\x53y[LEs7\\x20+ \\x28fun\\x63tion Od(){return UIm;}())]();\\r\\x0a\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif " ascii
    $s16 = "x61\\x72\\x20\\x4dz\\x3dB\\x615\\x2eExpandE\\x6eviro\\x6ementStri\\x6egs(\\x4dq2 + Qx + (fun\\x63tion EHf(){return \\x57b8;}()))" ascii
    $s17 = "2eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){r" ascii
    $s18 = " \\x22ll\" + \"\";\\r\\nvar CZy = \"ll\" + \"\";\\r\\nvar Jl9\\x20= \"lllll\" + \"\"\\x3b\\r\\nfunction If(YBe){return YBe;\\x7d" ascii
    $s19 = " +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){return " ascii
    $s20 = "var Dr \\x3d \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\nv\\x61\\x72 B\\x768 = \"l\\x65n\" + \"\";\\r\\nfunction Zk(KH" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}