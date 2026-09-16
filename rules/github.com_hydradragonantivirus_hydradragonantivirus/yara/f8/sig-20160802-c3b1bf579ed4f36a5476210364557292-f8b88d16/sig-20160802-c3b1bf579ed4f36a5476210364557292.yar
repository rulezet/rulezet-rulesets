rule sig_20160802_c3b1bf579ed4f36a5476210364557292 {
  meta:
    description = "datamaliciousorder - file 20160802_c3b1bf579ed4f36a5476210364557292.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eb155e66f584cc1dae80f2770650b65278ba8341547e6bcf36ecbfced3b417d"

  strings:
    $s1  = "    var aBm = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "20Sy=WScript[(func\\x74ion Rh1(){return \\x44e;}()) +\\x20A\\x7a4 + UYl\\x20+ (function \\x41Zx0(\\x29{\\x72eturn Xp;}())]\\x28P" ascii
    $s3  = "\\x65) {WScr\\x69p\\x74[DU\\x727 + (function Yk(){return XEa;}())](1000); continue;};\\r\\n} while (\\x55z\\x29\\x3b\\r\\n\\r\\n" ascii
    $s4  = "\\x0d\\n\\x0d\\nfor (var OPj=0; OPj \\x3c Pe\\x5bQSc + (funct\\x69on FTj(){return OXv9;}())]; OPj++)\\r\\n{\\r\\n\\ttry \\r\\n" ascii
    $s5  = "\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz6" ascii
    $s6  = "va\\x72 \\x58O\\x66 = \\x22Ob\"\\x20+ \"\";\\r\\nvar NFm = \"eate\\x22 + \"\\x22\\x3b\\r\\nvar Bv = \"Cr\\x22 +\\x20\"\"\\x3b\\r" ascii
    $s7  = " \\x2b \"\";\\r\\nvar Tw = \"\\x52e\" + \"\"\\x3b\\r\\nf\\x75nc\\x74ion AJ\\x614\\x28Xj6){return Xj6;};funct\\x69on Yc9(G\\x6a){" ascii
    $s8  = "o];}\\r\\n\\t\\tDq.push(String[WQh(In\\x29 + VWu1(KMf) +\\x20RJx + Vz6(Mi\\x34)](EFq7));\\r\\n\\t\\x7d\\x0d\\n\\t\\r\\n\\tO\\x67" ascii
    $s9  = "20Aa6 = \"pe\"\\x20+\\x20\"\";\\x0d\\nvar M\\x620 \\x3d \\x22ty\" + \"\";\\r\\nvar Si4 = \"o\\x70en\" + \"\";\\r\\nfunction Tf5" ascii
    $s10 = " + \\x22\";\\r\\nvar NLs = \".c\" + \"\";\\r\\nvar Vc \\x3d \"aw\" + \"\";\\r\\nfunction AFs(\\x54Gr\\x34){return TGr4;};v\\x61r" ascii
    $s11 = ")\\x0d\\n\\t\\t\\x7breturn tr\\x75e;}\\r\\n\\telse\\r\\n\\t\\t{return false;}\\x0d\\n};\\r\\n\\r\\x0a\\r\\nfunction KTb8\\x20/* " ascii
    $s12 = "UAm8+NUm5 +\\x20QTb2 + Rj3+MWq0 + (func\\x74ion UDw9(){return Th;}())+Ev8(ANx) + Rw+ISm, Kx2(SU\\x662\\x29+(f\\x75ncti\\x6fn WJf" ascii
    $s13 = "i++) s[i] = mash(Gz);\\r\\nmash = \\x6eull;\\r\\nvar ra\\x6edom = funct\\x69on( r\\x61\\x6ege ) {\\r\\nreturn Math.floor(ra\\x6e" ascii
    $s14 = "Pj <\\x20Tf0\\x5bJQu(\\x51\\x53\\x63) + (functi\\x6fn Cn2(){return OXv9;\\x7d())];\\x20OPj++)\\r\\n\\x09\\x7b\\x0d\\n\\t\\tva\\x" ascii
    $s15 = "Pl + (function STs6(){retur\\x6e QLw0;}()) + Xj(Br\\x35) + LGb + VUs1 + Sh \\x2b \\x54e\\x30(Wj6), Yp +\\x20NRk1 + Kw \\x2b Od +" ascii
    $s16 = "n WDf\\x32(){return RAx6;\\x7d()) + QLm\\x20+ Ml);\\r\\nvar Mz=Ba5.Expand\\x45n\\x76ironmentStri\\x6egs(RIh + V'+''+'Ho\\x28Er4)" ascii
    $s17 = ";\\r\\nv\\x61'+''+'r Ep3 = \"43\\x22\\x20+ \"\";\\r\\nvar \\x56h = \"th\" + \"\";\\r\\nvar WKb = \"leng\" + \"\";\\r\\nfunction " ascii
    $s18 = "[Lr(X\\x4fs) + Yv](HG\\x6c, ERb[OEq6++ % ERb[QSc \\x2b OXv9]\\x5d, false);\\r\\n\\t\\t\\tSy[(function Li4(\\x29{return Fc;}())]" ascii
    $s19 = "=RJp2\\x20+ (\\x66unction Rk2\\x28){re\\x74urn ZAe;}()) + (functi\\x6fn Kf6(){return LJa;}()\\x29;\\r\\n\\r\\nfunction uheprng()" ascii
    $s20 = " Ad1(QMf) + JHt6 + Vf3(DIl4) +\\x20(function XDd9(){ret\\x75rn\\x20DSn;}\\x28))](OPj);\\r\\x0a\\t\\tif (EFq7 < \\x284 \\x2a 32" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}