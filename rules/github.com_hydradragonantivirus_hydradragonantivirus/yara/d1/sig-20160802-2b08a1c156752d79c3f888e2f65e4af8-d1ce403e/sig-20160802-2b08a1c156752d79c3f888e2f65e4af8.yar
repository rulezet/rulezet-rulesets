rule sig_20160802_2b08a1c156752d79c3f888e2f65e4af8 {
  meta:
    description = "datamaliciousorder - file 20160802_2b08a1c156752d79c3f888e2f65e4af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11a7d05add63a178f96fb0b954e82a5fac39c37c51e757e305b94c4fe7b5ca29"

  strings:
    $s1  = "    var aVKo = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nreturn (\\x6e >>> 0) * 2.\\x3328306436538\\x36963e-\\x31\\x30;\\r\\n} else n =" ascii
    $s3  = "bXs5 + Lq3+Wc+(\\x66unction AXa(){return NL\\x73;}()\\x29];\\r\\nvar B\\x615=WScript[Je4(Ci2) + KQd9(Oj6) + FJq(IVm) + (fun\\x63" ascii
    $s4  = " Xt6\\x29;\\r\\nvar UWy4=Pe0[QSc + (funct\\x69on LBy(){return OXv9;\\x7d\\x28\\x29)];\\r\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r" ascii
    $s5  = "\\x45t1\\x5d(RCn + (function JYj5(){return IDj;}()) + \\x4fj9);\\r\\n\\t\\tbrea\\x6b;\\r\\n\\t}\\r\\n\\tcatch\\x20(e) {WScript[S" ascii
    $s6  = "t\\x09{var \\x45No=Sq\\x5bEF\\x71\\x37];}\\r\\n\\t\\x09HFz[(fun\\x63\\x74ion Gk(){return RUn9;}()) + JVi](ENo);\\r\\n\\t};\\r\\n" ascii
    $s7  = "\\x203605\\x3b\\r\\nvar\\x20UMc=\"4\\x337\";\\r\\n\\r\\nvar ERb=[SUf2'+''+'\\x2bKx2 + (function Fb(){return E\\x69;\\x7d())+Qc" ascii
    $s8  = "\\x3b continu'+''+'e;};\\r\\n} while (Uz)\\x3b\\r\\n\\r\\nWScr\\x69pt\\x2eQuit(0);\\r\\n\\r\\nfunction BKw(D\\x48f1 /* k \\x20*" ascii
    $s9  = "\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retur" ascii
    $s10 = "72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){" ascii
    $s11 = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii
    $s12 = "Sq[-6592 + 6770]=253;\\r\\nSq[9632]=2\\x354;\\r\\nSq[\\x31\\x360]=255;\\r\\n\\t\\r\\n\\tvar HFz\\x3dn\\x65\\x77 Array();\\r\\n" ascii
    $s13 = "s\\x68 = null\\x3b\\r\\nvar random = fu\\x6e\\x63\\x74ion( \\x72ange\\x20) {\\x0d\\nreturn Math.floor(range * (\\x72awp\\x72ng()" ascii
    $s14 = "OXv9]\\x3b OPj++)\\r\\x0a\\t{\\x0d\\n\\t\\tREt2\\x3d(\\x52Et2\\x20+ DHf1[OPj]) % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm)" ascii
    $s15 = "ar Q\\x78 =\\x20\"EMP\" + \"\";\\x0d\\nvar Mq2 = \"%T\\x22 + \"\";\\r\\nfun\\x63tion B\\x5ab(YSa){return YSa;};var W\\x4dp = \"l" ascii
    $s16 = "d;\\r\\n\\r\\n\\r\\nfunctio\\x6e NFc(Tf0)\\r\\n{ \\x20 \\r\\nvar \\x53q=new Array();\\r\\n\\t\\r\\x0a\\x53q[2071\\x20- 1872]=128" ascii
    $s17 = "6fn Zq9(\\x29{retur\\x6e Nl;}())\\x2bWn1+RWi+Po+Cy5 + \\x4en5+(function GNn(){return FYs1;}()), Rj3(\\x53j5\\x29+WSb0+\\x28\\x66" ascii
    $s18 = "x61r Id=NVd[QS\\x63\\x20+ OXv9];\\r\\nvar Pe0=(Dv3 + KJd + (fun\\x63\\x74io\\x6e IMn(){return CZi8;}())\\x2c Zs5 + Te1 + Su(MSl" ascii
    $s19 = "128) \\r\\n\\t\\t\\t{\\x45F\\x717=E\\x4eo;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7=P\\x617[ENo];}\\r\\n\\t\\t\\x44q.push(String[Kt" ascii
    $s20 = "var BSs4 \\x3d \\x221123\"\\x20+ \"\";\\r\\nvar Mz9=(\\x42Ss4 +\\x20If(Kg), Jl\\x39 \\x2b C\\x5ay + IIk2 + (function NKy0(){re" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}