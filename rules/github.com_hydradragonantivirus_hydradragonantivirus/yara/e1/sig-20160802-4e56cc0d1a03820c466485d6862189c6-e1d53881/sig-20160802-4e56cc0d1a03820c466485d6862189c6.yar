rule sig_20160802_4e56cc0d1a03820c466485d6862189c6 {
  meta:
    description = "datamaliciousorder - file 20160802_4e56cc0d1a03820c466485d6862189c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85b3cc788a4dc19ed5d7a404fba1e57d74decf3cdded23654d8d4d19c8881d39"

  strings:
    $s1  = "    var aUCe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "r t = 1768863\\x20* s[\\x70] + c\\x20* 2.3\\x32830643653869\\x363e-10;\\r\\nr\\x65turn s[p] \\x3d t -\\x20\\x28c = t | 0);\\x0d" ascii
    $s3  = "ar random = fu\\x6ection( \\x72ange ) {\\r\\nreturn \\x4d\\x61\\x74h.flo\\x6fr(ra\\x6ege \\x2a (rawprng() + (rawprng() * 0\\x782" ascii
    $s4  = "reak;\\x0d\\n\\t}\\r\\n\\tca\\x74ch\\x20(e) {WScript[STs6 + (function CKv9(){retur\\x6e Ly0;}())](1\\x3000); continue\\x3b};\\r" ascii
    $s5  = "\\x52Cn=RJp2 + VJy + YVo(Ht)\\x3b\\r\\n\\r\\nfunction uheprng() {return (function() {\\r\\nvar o\\x20=\\x2048,\\x20c = \\x31, p " ascii
    $s6  = "\\t\\x09{return true;}\\r\\n\\telse\\r\\n\\t\\t{retur\\x6e f\\x61\\x6c\\x73e;}\\r\\x0a};\\r\\n\\r\\n\\r\\nfu\\x6ection KTb8 /* k" ascii
    $s7  = "\\x70e\" + \"\";\\r\\nfunction KEx3(TEw){retu\\x72n TE\\x77;};function OH\\x73\\x30(Lo){\\x72e\\x74urn L\\x6f;};var Ly0 = \"p\" " ascii
    $s8  = "\\x61r Xl2 = \"ta\" + \"\";\\r\\nv\\x61r MHr = \"to\" + \"\\x22;\\r\\nvar QE\\x77 = \\x22//\" + \"\";\\r\\nfunction Vs(\\x59\\x7" ascii
    $s9  = "nvar Fe =\\x20\"at\" + \"\"\\x3b\\r\\x0avar Jm = \"Cre\\x22 + \"\";\\r\\nvar\\x20Hg = \"qx0t\" + \"\";\\r\\nfunc\\x74ion Bb5(IJh" ascii
    $s10 = "x20+ Oz7+U\\x652+UDw9 + TQa7+Kg3+QRy5 +\\x20ZZs+Pi8+Xh1, Vs(NJa) + WR\\x721+QEw+\\x4dHr + TNk4\\x28Xl2)+(function RG\\x6c2(){ret" ascii
    $s11 = "Tf2(F\\x46m), E'+''+'Rb[OEq6++ \\x25 ERb[QSc + O\\x58v9]], false)\\x3b\\r\\n\\t\\t\\tSy\\x5b(fu\\x6ectio\\x6e Gi2\\x28){return " ascii
    $s12 = "Qb + XEh];\\r\\n\\r\\nfor (\\x76ar OPj=0; OPj < Pe[QSc + (function FT\\x6a(){re\\x74urn OXv\\x39;}()\\x29]\\x3b OPj++)\\r\\n{\\r" ascii
    $s13 = "r\\n\\r\\nfun\\x63tion Ly(\\x44Hf1 /* k  */)\\r\\n{\\r\\x0a \\x20  var Pa7=\\x6eew Array();\\r\\n\\t\\r\\nPa\\x37[128]\\x3d199;" ascii
    $s14 = "n'+''+'function Tf2(Hg0){return Hg0;\\x7d;va\\x72 FFm = \"GE\\x54\"\\x20+ \\x22\";\\r\\nva\\x72 Hp0 =\\x20\"n\\x22 + \"\";\\r\\n" ascii
    $s15 = " + K\\x4ad\\x20+ (f\\x75nction IMn(){return CZi8;}()\\x29, Zs5 + Te1 + Su(MSl)\\x20\\x2b\\x20Xt6);\\r\\nvar UWy4=Pe0[QSc + (func" ascii
    $s16 = "2=(REt2 + DHf1[OPj]) \\x25 0x10000\\x3000\\x30;\\r\\n\\t};\\r\\x0a\\t\\x69f (\\x52Et2 != Cm) {return [];};\\r\\n\\t\\r\\n\\tretu" ascii
    $s17 = "rh\" + \"\";\\r\\nvar Zf = \"a\" + \"\";\\r\\nvar TEd = \"ep\" + \"\";\\r\\nvar Gr4 = \"lr\" + \"\";\\r\\nfun\\x63ti\\x6fn TNk4(" ascii
    $s18 = "t\\x09else \\r\\n\\t\\t\\t{EFq\\x37=\\x50a7[\\x45No];}\\r\\n\\t\\tDq.push(String[\\x4bt + Fd + XUw\\x20+ Eo6](EFq7));\\r\\n\\t}" ascii
    $s19 = "\"th\" + \"\";\\r\\nvar WKb = \"leng\" \\x2b \"\\x22;\\r\\nfunction\\x20Su(\\x53\\x48v4){return SH\\x764;\\x7d;var Xt6 = \"ll\" " ascii
    $s20 = "r\\x0avar \\x45Rb=[SU\\x662+DFm0\\x2bVm+(func\\x74ion Zq9(){return \\x4el;}())+Wn1+RWi+Po+VWh0 + ADx, Kx2(SUf2)+G\\x4en+\\x51Tb2" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}