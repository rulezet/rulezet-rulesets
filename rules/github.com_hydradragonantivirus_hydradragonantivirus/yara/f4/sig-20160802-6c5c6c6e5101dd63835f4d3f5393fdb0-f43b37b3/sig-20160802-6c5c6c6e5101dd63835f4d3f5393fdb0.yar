rule sig_20160802_6c5c6c6e5101dd63835f4d3f5393fdb0 {
  meta:
    description = "datamaliciousorder - file 20160802_6c5c6c6e5101dd63835f4d3f5393fdb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db0bd75dae1a05acc4488343e5d7344e60d4de5767959db8aeeeb4ed56c88249"

  strings:
    $x1  = "    var aHKx3 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar " ascii
    $s3  = "=new Array();\\r\\n\\t\\x0d\\nSq\\x5b2071 - 18\\x372]=128;\\r\\nSq[252]=129;\\r\\nSq[233\\x5d=130;\\r\\x0aSq[226]=-370 + \\x3501" ascii
    $s4  = " * 2.3\\x32830\\x364365386963e\\x2d10;\\r\\x0areturn s[p] = t - (c =\\x20t | 0);\\r\\n}return rando\\x6d;}());};\\r\\n\\r\\nfunc" ascii
    $s5  = "x63ti\\x6fn JYj5(){return IDj;}()) + Oj9);\\r\\n\\t\\tbreak;\\x0d\\n\\t}\\r\\n\\tcatch \\x28e) {WScript[S\\x54s6 + (function CKv" ascii
    $s6  = "4cy0;}())]'+''+'(1000); continue;}\\x3b\\r\\n} whil\\x65 (\\x55z);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\x0afunction\\x20B\\x4b" ascii
    $s7  = "\\x20\"le\\x6eg\" + \"\";\\r\\x0afunction Su(\\x53H\\x764){return SHv4;};var\\x20Xt6\\x20= \"ll\" + \"\";\\r\\nvar M\\x53l = \"l" ascii
    $s8  = "\\x72 EGw = \"ll\" + \"\";\\r\\nvar Mj = \"lllll\\x22 + \"\";\\r\\x0afunction Oq(Pf\\x30){return Pf0;\\x7d;function \\x53Gv(KLy" ascii
    $s9  = "\\x5ab(Wc0)\\x20+ PMq2(EIk)\\x20+ Y\\x46e + (f\\x75nctio\\x6e Tv(\\x29{return JHu8;}())]\\x28Ea+J'+''+'\\x57z3+T\\x766+Ep + \\x4" ascii
    $s10 = "65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s11 = "(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(" ascii
    $s12 = "x780](Sy[(function Xz\\x33(\\x29{return Qa;}()) + H\\x732 + Sa\\x30\\x5d);\\x0d\\n\\t\\tARt\\x5bPCl +\\x20Fy\\x5d=1 * 0;\\r\\n" ascii
    $s13 = "=[JZe + Sk + Wi2\\x20+ (function Ua(){return INw6;}()) + W\\x6b9 + E\\x731 + VOw\\x2c Ft \\x2b \\x44Qb + XEh];\\r\\n\\r\\nfo\\x7" ascii
    $s14 = "x68\\x2bUIk+(function \\x56Ed(){return Uf;}()) + (\\x66unct\\x69on Rz(){r\\x65turn Je4;}())+JFw(EVb) + FJq+Bb5(Hx)];\\r\\nvar Ba" ascii
    $s15 = "l\" + \"\";\\r\\nfunction If(\\x59Be){return YBe;};var Kg = \"132\" + \"\";\\r\\nv\\x61r BSs4 = \"1123\\x22 + \"\";\\r\\nvar Mz9" ascii
    $s16 = "tion\\x20GNn(){\\x72eturn \\x46Ys1;}())\\x2bRj3(Sj5), WSb0+(f\\x75nction Ry0(){return Qq;}())+NAm9+MSc5 + Q\\x52y5\\x2bRTo2(L\\x" ascii
    $s17 = "cri\\x70t[Wc0\\x20+ (function P\\x58o9(){return \\x45Ik;}()) + YFe +\\x20(fun\\x63ti\\x6fn SSq(){r\\x65\\x74urn JHu8;}())](\\x28" ascii
    $s18 = "{return T\\x58\\x68;};var Sj5 \\x3d \"x6\"\\x20+ \"\\x22;\\r\\nva\\x72 FYs1 = \"/goi\" \\x2b \"\"\\x3b\\r\\nvar Nn5\\x20= \"pl\"" ascii
    $s19 = "uncti\\x6fn\\x20IMn(){retur\\x6e\\x20CZi8;}()), Zs5 + Te1 + Su(MSl) + Xt\\x36\\x29;\\r\\x0avar UWy4=Pe0[QSc + (fun\\x63tion LBy(" ascii
    $s20 = "(functio\\x6e Er8(){return \\x56Jk5;}(\\x29\\x29 \\x2b \\x4aGm3](R\\x4ap2, Ya);\\r\\n\\t\\x09ARt[NAe\\x30 + PJh]();\\r\\n\\t\\r" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}