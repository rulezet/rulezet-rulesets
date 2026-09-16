rule sig_20160802_186fae7306b9b64554307fe6bec5f8f0 {
  meta:
    description = "datamaliciousorder - file 20160802_186fae7306b9b64554307fe6bec5f8f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fc4aa28ace0f20de037ca87d95533c923bd64c023522317147ee252d8a4cc5c"

  strings:
    $x1  = "    var aUCe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "GTn6(DXs5)\\x2b(function Ii(){return N\\x4cs;}(\\x29) + RGl2+\\x48h+IVm];\\r\\nvar Ba5=WScript[RJe4 + LFp + As3 + (fun\\x63tion" ascii
    $s3  = "\\r\\x0avar Uh6 = \"len\\x22 + \\x22\\x22;\\r\\nfunc\\x74i\\x6f\\x6e KEx3(TEw){return TEw;};v\\x61r Aa9 =\\x20\"GET\"\\x20+ \"\"" ascii
    $s4  = "63e-1\\x30;\\r\\nre\\x74urn s\\x5bp] = t - (c \\x3d t | 0);\\r\\x0a}return ra\\x6edom;\\x7d\\x28));};\\r\\n\\r\\nfu\\x6e\\x63tio" ascii
    $s5  = ";\\x0d\\nvar UWy4=Pe0[QSc + (functio\\x6e LBy(){return OXv9;}(\\x29\\x29\\x5d;\\r\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Y" ascii
    $s6  = "53q[\\x45\\x46q7];}\\r\\x0a\\t\\tHFz[(f\\x75\\x6ection Gk(){return RUn9;}()) + JVi](ENo);\\r\\n\\t};\\x0d\\n\\t\\r\\n\\tret\\x75" ascii
    $s7  = "\\n{\\x0d\\n\\x09\\x74ry \\r\\x0a\\x09{\\r\\x0a\\t\\tvar Sy=WScript\\x5b(function Re1(\\x29{return RJ\\x654;}()) +\\x20(fu\\x6e" ascii
    $s8  = "x31](RCn + (function JYj5(){return IDj;}()) +\\x20Oj9);\\r\\n\\t\\tbre\\x61k;\\r\\n\\t}\\r\\n\\tcatc\\x68 (e) {WScript[SDb + IDo" ascii
    $s9  = "\\x72ipt[RJe4 + L\\x46p + (function CYi(){return As3;}()) + (function ELr4(){\\x72eturn Zu;}())](T\\x59j+Mf(Cc0)+Wt6+XOs\\x20+ Y" ascii
    $s10 = "\\nvar D\\x72 = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\x0a\\x76ar\\x20Bv8 = \\x22len\" + \"\";\\r\\nfunction Zk(KH" ascii
    $s11 = "\\t\\t\\x09{\\x45Fq7\\x3dENo;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EFq7\\x3dPa7[ENo];}\\r\\n\\x09\\tDq.push(String[Kt + Fd\\x20+ XUw" ascii
    $s12 = "4v \\x3d \"WaV\" + \"\"\\x3b\\r\\nvar Rh1 = \"8\\x74\" + \"\";\\r\\nva\\x72 RGn =\\x20\"jL\" + \"\";\\r\\nfunction Jn9(\\x4am3){" ascii
    $s13 = "=253;\\r\\nSq[9632]\\x3d254;\\r\\nS\\x71\\x5b160]=255;\\r\\n\\t\\r\\n\\tvar H\\x46z\\x3d\\x6eew Array();\\r\\x0a\\tfor (var OPj=" ascii
    $s14 = "d; OPj++)\\x0d\\n\\t\\x7b\\r\\n\\t\\tREt\\x32=\\x28REt\\x32 + DHf1[OPj]) % 0x100000000;\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {retu" ascii
    $s15 = "\"\";\\r\\nfunction DEk0\\x28Ja0\\x29{return Ja0;};functi\\x6fn\\x20P\\x4ah(\\x4dTj4){\\x72etur\\x6e MTj4;};va\\x72 RVy = \"e\" " ascii
    $s16 = "x20Ix6(){return E\\x54x9;}()\\x29\\x20+\\x20Z\\x5ac8](RJ\\x702, Ya);\\r\\n\\t\\t\\x41Rt[DEk0\\x28KCh5) + TZa + PJh(R\\x56y)]();" ascii
    $s17 = "Id=NVd[QSc \\x2b\\x20OXv9];\\r\\nvar Pe0=(Dv3 + KJd + (funct\\x69\\x6fn \\x49Mn(){return CZi8;}()), \\x5as5 + Te1 + Su(MSl) \\x2" ascii
    $s18 = "am\" + \"\";\\r\\x0avar Y\\x76 = \"St\" +\\x20\"\";\\r\\nva\\x72 XOs = \"DB\\x2e\" + \"\"\\x3b\\r\\n\\x66unction\\x20Vw3(NAa){re" ascii
    $s19 = "(){\\x72eturn \\x4el;}())+W\\x6e1+RWi+Po+Cy5 + Nn\\x35+(function GNn(){return FYs1;}())+QTb2, S\\x55y3\\x2b(funct\\x69\\x6fn Ry0" ascii
    $s20 = "ontin'+''+'ue;};\\r\\n} while (Uz\\x29;\\r\\n\\r\\nWSc\\x72ip\\x74.Quit(0);\\r\\n\\r\\nfunction BKw(\\x44Hf1 /* k\\x20 \\x2a\\x2" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}