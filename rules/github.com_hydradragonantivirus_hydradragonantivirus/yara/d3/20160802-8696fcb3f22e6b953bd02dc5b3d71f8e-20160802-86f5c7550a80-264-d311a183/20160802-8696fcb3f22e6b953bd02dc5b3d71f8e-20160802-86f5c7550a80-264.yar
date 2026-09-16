rule _20160802_8696fcb3f22e6b953bd02dc5b3d71f8e_20160802_86f5c7550a80_264 {
  meta:
    description = "datamaliciousorder - from files 20160802_8696fcb3f22e6b953bd02dc5b3d71f8e.js, 20160802_86f5c7550a80ea9976dff0137445eec4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a8747b32ba874f2535d2eaf212d5df79360f74c81beecacce162c2511598ba2"
    hash2       = "2b2cc95cc5029dfe206df9f641cfc1978d52a986276d7e9b72f155a36afbffb0"

  strings:
    $s1  = "''+'\\tWScript[L\\x4aa](1000);\\r\\n\\t\\x09\\t}\\r\\n\\t\\t\\tSy[Pc\\x30](LEs7,\\x20ERb\\x5bOEq6\\x2b+ % \\x45Rb[QSc + \\x4fX" ascii
    $s2  = "b\\r\\nvar\\x20Ba5=WScript[D\\x55m + Bb5 + (f\\x75nction IJm(){re\\x74urn \\x49Jh\\x3b}()) + Fl\\x32\\x5d((function RGn(\\x29\\x" ascii
    $s3  = "x3b continu\\x65;}\\x3b\\r\\n} while (Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\nfun\\x63tion BKw(DHf\\x31 /* L  */)\\r\\n{\\x0" ascii
    $s4  = "ction \\x4es5(){return LJa;}())\\x5d(\\x2d1\\x3310 + 1410);\\x0d\\n\\t\\t\\tcontin\\x75e;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\x0a\\t\\x" ascii
    $s5  = "c * 2.\\x33283\\x3064365386963\\x65-10;\\x0d\\nreturn s[p] = t - (c \\x3d t | 0);\\r\\n}return rand\\x6fm;}());};\\r\\n\\r\\nfun" ascii
    $s6  = " \\x28func\\x74ion LBy(){return OXv9;}())];\\x0d\\n\\r\\nvar GRx5=1;\\r\\nvar D\\x41\\x65\\x3d2;\\r\\nvar Ya=3607 - 3605;\\r\\nv" ascii
    $s7  = "x0avar Sq=ne\\x77 Array();\\r\\n\\t\\r\\nSq[2071 - \\x31872]'+''+'=\\x3128;\\r\\nSq[\\x3252]=129;\\r\\x0aSq[233]=130\\x3b\\r\\x0" ascii
    $s8  = "\\x52Wi+Po+\\x43y5 + N\\x6e5+(funct\\x69on GNn(){return F\\x59s1;}()), Rj3(Sj5)+WSb0+(function Ry0(){re\\x74ur\\x6e Qq;}(\\x29" ascii
    $s9  = "\\nvar Gr4 = \"/s\" + \"\";\\r\\nfunction TNk4(Xs5){return Xs5;};var Xl2 = \":/\\x22 +\\x20\"\";\\r\\nvar MHr = \"tp\" \\x2b\\x2" ascii
    $s10 = "\\n\\r\\nva\\x72 ERb\\x3d[SUf2\\x2bKx2 + \\x28function Fb(){return'+''+'\\x20Ei;}())+Qc4+(function Zq9(){r\\x65t\\x75rn Nl;\\x7d" ascii
    $s11 = "return Og;\\r\\x0a};\\r\\n\\r\\n\\r\\nf\\x75nction Vg8(Ec,\\x20D\\x48f1 \\x2f* L  */)\\r\\n{\\r\\n    var WHy\\x30=WScript[DUm" ascii
    $s12 = "x7breturn TEd;}()\\x29 + Zf+Hh+VUg + RUf+Cp +\\x20IHt+\\x28function \\x57c6(){return HPu9;}())+(function Mh(){return Re1;\\x7d()" ascii
    $s13 = "== 0x5a)\\r\\n\\t\\t{r\\x65t\\x75\\x72n true;}\\r\\n\\x09els\\x65\\r\\n\\t\\t{return \\x66alse;}\\x0d\\n};\\r\\x0a\\r\\n\\r\\nfu" ascii
    $s14 = "tion\\x20SGv(KL\\x795){re\\x74urn KLy5;\\x7d;function J\\x51u\\x28KKh4)\\x7bre\\x74urn KKh4;}\\x3bva\\x72 O\\x58v9 = \"gth\" + " ascii
    $s15 = "72 Y\\x44x4 = \"t.\" +\\x20\"\";\\r\\nvar Rn = \\x22ip\" + \"\";\\r\\n\\x76ar SWb\\x20= \"WScr\" + \"\";\\r\\nfunction \\x48Sw6(" ascii
    $s16 = "20\"th\" + \"\"\\x3b\\r\\nvar WKb = \\x22l\\x65ng\" + \"\";\\r\\nfunction \\x53u(S\\x48v4){return SHv4;};v\\x61r Xt6 = \"ll\"\\x" ascii
    $s17 = "]; OPj++)\\r\\n\\t{\\r\\n\\t\\tREt2=(\\x52Et2 + DHf\\x31[OPj]) % 0x10000\\x30000;\\r\\x0a\\t};\\r\\n\\tif (REt\\x32 != Cm) {retu" ascii
    $s18 = "[NNh + JZe + S\\x6b + Wi2 + (function BIy1(){return INw6\\x3b}()) \\x2b Wk9 + \\x45s1, \\x4eI\\x70 + XAi3 + Ic0 + \\x59v\\x33];" ascii
    $s19 = "push(Stri\\x6eg[CWx0 + FXe1\\x28Ne6) +\\x20Oy \\x2b Tl\\x38(J\\x63)](EFq7));\\x0d\\x0a\\t}\\r\\n\\t\\r\\n\\tOg=Dq\\x5bRq9]\\x28" ascii
    $s20 = "\";\\r\\nvar Jl9 = \"\\x6cllll\" + \"\";\\r\\nfunction If(YBe){return YBe\\x3b};var Kg = \"13\\x32\" + \"\";\\r\\nvar BSs4 = \"1" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}