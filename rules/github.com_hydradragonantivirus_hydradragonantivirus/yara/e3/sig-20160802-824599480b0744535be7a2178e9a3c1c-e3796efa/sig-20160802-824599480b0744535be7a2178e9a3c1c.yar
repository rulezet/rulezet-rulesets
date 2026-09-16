rule sig_20160802_824599480b0744535be7a2178e9a3c1c {
  meta:
    description = "datamaliciousorder - file 20160802_824599480b0744535be7a2178e9a3c1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "967de769a1fe0ac3dc7c8e1c4b36848fbb16b4cdf8717ce3ee3f04b603730356"

  strings:
    $s1  = "    var aNh = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "1;\\r\\x0avar DA\\x65=2;\\r\\nv\\x61r Ya=360\\x37 - 3605;\\r\\nvar UMc\\x3d\"437\";\\r\\n\\r\\nvar ERb=[SUf2+Kx2 + (function F" ascii
    $s3  = "53;\\r\\x0aSq[\\x39632]=2\\x354;\\r\\nSq[160]=255;\\r\\n\\t\\r\\n\\tva\\x72 HFz=new Array();\\r\\n\\t\\x66or (var\\x20OPj=6\\x39" ascii
    $s4  = " Jq;}())\\x20\\x2b Re\\x31\\x2b\\x42\\x625\\x28G\\x48x\\x29];\\r\\nvar\\x20Ba5=\\x57Script[W\\x630 +\\x20(function PXo9\\x28){re" ascii
    $s5  = "\\x702 + RIh + (function\\x20Zo4(){return JVc3;}\\x28))\\x3b\\r\\n\\r\\nfunction uhe\\x70rng() {\\x72eturn\\x20(function() {\\r" ascii
    $s6  = "\\x0d\\nmas\\x68 = nu\\x6cl;\\r\\nv\\x61r random = f\\x75nction( r\\x61nge ) {\\r\\nr\\x65turn\\x20\\x4dath.floor(r\\x61\\x6ege " ascii
    $s7  = "\\r\\nvar OOh = \"h\\x22 + \\x22\";\\r\\nvar Ud8 = \"g\\x74\" + \"\";\\r\\nvar FOp3\\x20= \"len\\x22 + \\x22\"\\x3b\\r\\nfunc\\x" ascii
    $s8  = "\\x7d()) + VJk5 + \\x52Vy(J\\x47m3)])\\x3b\\r\\n\\t\\tARt[NAe\\x30 + PJh + MTj4]=1 * 0;\\r\\n\\x09\\tARt[(\\x66unction AMj0(){re" ascii
    $s9  = "\\treturn HFz;\\r\\n};\\x0d\\x0a\\x0d\\n\\r\\nf\\x75n\\x63tion Ly(DHf1 /* \\x79  */)\\r\\n{\\r\\n \\x20  var \\x50a7=new Array()" ascii
    $s10 = "{return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0d" ascii
    $s11 = "-= n;\\r\\nn\\x20+= h * 0x100000000;\\r\\n}\\r\\nreturn (n >>>\\x200) * \\x32.328306\\x343653\\x386\\x3963e-10;\\r\\n} else \\x6" ascii
    $s12 = "1 = \"o\"\\x20+ \"\";\\r\\x0avar\\x20Jq = \"4z\" + \"\";\\r\\nf\\x75nct\\x69\\x6fn Je4(LFp){retur\\x6e LFp;};function KQ\\x649(Z" ascii
    $s13 = "20\":/\\x22 + \"\";\\r\\nvar Hu = \"tp\" + \"\";\\r\\nvar \\x57Sb0 = \"ht\" + \"\";\\r\\nfunction\\x20Rj\\x33(TXh){return TXh;" ascii
    $s14 = "ion VOy\\x37(DHf\\x31 /* y  */\\x29\\r\\n{\\r\\n\\tif \\x28\\x44Hf\\x31[0]== 0x4D\\x20&& DHf1\\x5b1]== 0x5a)\\r\\n\\x09\\t{retur" ascii
    $s15 = "65n\" + \"\";\\r\\nfunction DLr5(Bx7){retu\\x72n Bx\\x37;};function Yj\\x28\\x4bf1){r\\x65t\\x75rn Kf\\x31;};var Sh = \"p\" + \"" ascii
    $s16 = "R\\x56\\x79(Mb0\\x29{return Mb0;\\x7d;var\\x20J\\x47m3\\x20= \"o\\x64y\" + \"\\x22;\\r\\nvar\\x20\\x56Jk5 = \"eB\" + \"\";\\r\\x" ascii
    $s17 = " + \"\";\\r\\nvar Wc0 =\\x20\"\\x43re\\x61\" + \"\";\\r\\nfunct\\x69on Bb5\\x28IJh){return IJh;};v\\x61\\x72 GH\\x78 = \"4c\\x76" ascii
    $s18 = " Dh5 +\\x20C\\x618 + (functi\\x6f\\x6e EPo(){return Wp;}()) + Xc6 + Zb1(Y\\x55\\x63) \\x2b ZDo7 + Ol + HMr4 + TXe\\x38 + Gs4 + P" ascii
    $s19 = " Te1 +\\x20Su(M\\x53l) + \\x58t6);\\r\\n\\x76ar UWy4=Pe0[QSc + (f'+''+'\\x75nction LBy(){return OXv9;}())\\x5d;\\x0d\\n\\r\\nvar" ascii
    $s20 = "+ \\x44Qb \\x2b\\x20XEh, XRu \\x2b\\x20Sp +\\x20Ck9\\x28Lw0) + Br5\\x5d;\\r\\n\\x0d\\nfor (var OPj=0; O\\x50j < Pe[QSc + (functi" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}