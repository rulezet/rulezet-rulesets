rule _20160802_471c1cf0492e25b60a87b9af7118b28d_20160802_dd4900722aab_281 {
  meta:
    description = "datamaliciousorder - from files 20160802_471c1cf0492e25b60a87b9af7118b28d.js, 20160802_dd4900722aab50cadcb2f6e7d5ae046e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc02496821d2c2a046ebbe4dacc6baaf9fb4ec20a28cd2ee96a55b24d3bcbc55"
    hash2       = "d25b5ee4e0b1eb78fd4f7b95e2132bad594ba21ca6c7349c68ca624c7234f0d9"

  strings:
    $s1  = "310 + 1410);\\r\\n\\x09\\t\\x09c\\x6fntinue;\\r\\n\\t\\t\\x7d\\r\\n\\t\\t\\r\\n\\t\\tva\\x72 ARt=WScript\\x5bR\\x4ae4 + LFp + (f" ascii
    $s2  = "WScript[(f\\x75n\\x63\\x74ion \\x52\\x651(\\x29{return RJe4;}()\\x29 + (function M\\x68(){return \\x4cFp;}()) \\x2b As\\x33\\x20" ascii
    $s3  = "=WScript[RJe\\x34 + LFp + As3 + (functio\\x6e Wc6\\x28){return \\x5au;}())](Ot8 + DWb8 + SSq);\\r\\nvar Mz=Ba5.ExpandEnv\\x69ron" ascii
    $s4  = " + Oj9);\\r\\n\\t\\tbreak;\\r\\n\\t}\\r\\n\\tcatch (e\\x29 {WScript[SD\\x62 + IDo](1000)\\x3b continue;};\\r\\n} while (Uz);\\r" ascii
    $s5  = "\\x63tion Oi\\x35(\\x29{return E\\x47w;}()) + Dh5 + \\x43a8 + (f\\x75nction EPo(\\x29{retu\\x72\\x6e Wp;}()) + Xc6 + Zb1(YUc\\x2" ascii
    $s6  = "\\nfunction\\x20VOy\\x37(DHf1 /* k  \\x2a/)\\r\\n{\\r\\x0a\\tif \\x28DHf1[0]== 0x4D &\\x26\\x20DHf1[1]=\\x3d 0x5a)\\r\\n\\t\\t{r" ascii
    $s7  = "var\\x20EGw =\\x20\"ll\" + \"\"\\x3b\\r\\nvar Mj = \\x22l\\x6clll\" \\x2b \"\\x22;\\r\\nfunctio\\x6e O\\x71(P\\x660){return Pf0;" ascii
    $s8  = "+\\x20(function IMn(){return CZi8;\\x7d()), Zs5 + Te1 + Su(M\\x53\\x6c\\x29 + Xt6);\\r\\nvar UWy4=Pe0[QSc + (function LBy(){\\x7" ascii
    $s9  = "nf\\x75n\\x63tion \\x49f(YBe){return YB\\x65;};va\\x72 Kg = \"132\\x22 \\x2b \"\\x22;\\r\\nvar BSs4 = \"1123\" + \"\";\\r\\nva" ascii
    $s10 = "turn As3;\\x7d()) + (function ELr4(){return Zu;}())](TYj+Mf(Cc0)+Wt6+\\x58Os + Yv0 + Xp6(X\\x66));\\r\\n\\t\\tARt[IDg]()\\x3b\\r" ascii
    $s11 = ")\\x20% \\x30x100000\\x300\\x30;\\r\\n\\x09};\\r\\n\\tif (REt2 != Cm) {return [];};\\r\\n\\t\\r\\n\\treturn DHf1 /* k  */;\\r\\n" ascii
    $s12 = " (var O\\x50j=0; OPj < Pe[QSc + (function FTj(){r\\x65turn \\x4fXv9;}()\\x29]; O\\x50j\\x2b+)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\x0d" ascii
    $s13 = "ash(Gz);\\r\\nmash \\x3d null;\\r\\nvar random \\x3d f\\x75nction( range ) \\x7b\\r\\nretur\\x6e Math\\x2efloor(range * (\\x72aw" ascii
    $s14 = "telse\\x0d\\n\\t\\x09\\x7b\\x72etur\\x6e false;}\\r\\n\\x7d;\\r\\n\\r\\n\\r\\nfunction\\x20\\x4bTb8 /* k \\x20*/(\\x45c)\\r\\n" ascii
    $s15 = "x29 + \\x55\\x68\\x38\\x3b\\r\\x0av\\x61r\\x20RCn=RJp\\x32 + I\\x46j0 + USw\\x3b\\r\\n\\r\\x0afunction uhepr\\x6eg() {return (fu" ascii
    $s16 = "a7[\\x45No];}\\r\\n\\t\\tDq.push(String[\\x4bt + Fd + XUw\\x20+ Eo6](EFq7));\\r\\n\\t}\\r\\n\\t\\r\\n\\x09Og=Dq[RFj]\\x28\"\")" ascii
    $s17 = "If(Kg), Jl9 + CZy + IIk2 +\\x20(function NKy0\\x28){r\\x65turn EYf;}()));\\r\\nvar Te=Mz\\x39[QSc\\x20+ OXv9]\\x3b\\r\\nvar NVd=" ascii
    $s18 = "s = \"o/w\" + \"\";\\r\\nfunction GTn6(Wc){return Wc;};var DXs5 = \"nf\" + \\x22\";\\x0d\\nvar Oj2 = \"erd.i\" +\\x20\\x22\";\\r" ascii
    $s19 = "y5\\x29{return KLy5;};fun\\x63tio\\x6e \\x4aQ\\x75\\x28KK\\x68\\x34){r\\x65turn K\\x4bh4;};var OXv9 \\x3d \\x22gth\\x22 + \"\";" ascii
    $s20 = " n = 0xefc8249d;\\r\\n};\\r\\nreturn mash;\\r\\n}\\r\\n\\r\\nvar P\\x65=[ZAe + PAn \\x2b Bv7 + Aw +\\x20Kf6 +\\x20\\x4cf7 + Bq1 " ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}