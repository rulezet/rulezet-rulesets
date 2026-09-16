rule sig_20160802_d5a4cdcfbf51999c08e1071140ba9ade {
  meta:
    description = "datamaliciousorder - file 20160802_d5a4cdcfbf51999c08e1071140ba9ade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68b55c205a905030d0477f70ff5f119b159e3674c02bace8ff1a26aa6519bc40"

  strings:
    $s1  = "    var aSs = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "} while (Uz\\x29;\\r\\x0a\\r\\nWScript\\x2eQuit(\\x30\\x29;\\r\\n\\r\\nfunction BKw(DH\\x66\\x31 /* \\x79  */)\\r\\n{\\r\\n\\tva" ascii
    $s3  = "())+(f\\x75nction Mh(){return Re1;\\x7d())];\\r\\nvar Ba5=WScript[DUm + Bb5 + (function IJm(){\\x72e\\x74urn\\x20IJh;\\x7d()) + " ascii
    $s4  = "Pa7[253]=1\\x378\\x3b\\r\\nP\\x617[254]=19363 - 9731;\\r\\nPa\\x37[255]=160;\\r\\n\\x09\\r\\n\\tvar Dq=new Array();\\r\\x0a\\tva" ascii
    $s5  = "\\n\\t\\tARt\\x5b\\x55b](Sy[ZWl + (\\x66unct\\x69on Er\\x38(){return R\\x4ds4;}()) + VJk5 + RVy(JG\\x6d3)]);\\r\\x0a\\t\\tARt[NA" ascii
    $s6  = "\\nvar random = fu\\x6ecti\\x6fn( range ) \\x7b\\r\\nre\\x74urn Math.floor(range *\\x20(rawprng() + (rawprng(\\x29 * 0x200000 | " ascii
    $s7  = "var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s8  = "\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){ret" ascii
    $s9  = "t\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){return" ascii
    $s10 = "'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar LF" ascii
    $s11 = "b \\x22\";\\r\\nvar Gr4 = \"/s\" + \"'+''+'\";\\r\\x0af\\x75nction T\\x4ek4(Xs5){return Xs5;\\x7d;var Xl2\\x20= \":/\" \\x2b \"" ascii
    $s12 = "c4 + H\\x670(Yj0)](Qg(Oi0), ERb[OEq6++ % ERb[QSc + OXv9]], false);\\x0d\\n\\t\\t\\tSy[TTv(HXb)]\\x28);\\r\\n\\t\\t}\\r\\n\\t\\t" ascii
    $s13 = "())+Wn1+RWi+Po+Cy\\x35\\x20+ Nn5+(functio\\x6e GNn(){return FYs1;}())\\x2c Rj3\\x28Sj5)+WSb0\\x2b(function Ry0(){return Qq;}())+" ascii
    $s14 = "turn Fl2;}()\\x29](Oe3+Vj+Vv+GT\\x67 + XHb\\x30\\x20+\\x20L\\x757);\\r\\n\\t\\x09ARt[RFc4 + \\x59j0]();\\r\\x0a\\t\\tARt[NAc3 + " ascii
    $s15 = "x2d 6938\\x3b OPj \\x3c T\\x66\\x30[JQu(Q\\x53c) + (fu\\x6e\\x63tion Cn2(){return OXv9;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tv\\x61" ascii
    $s16 = "72n mash\\x3b\\r\\n}\\x0d\\x0a\\r\\nvar Pe=\\x5b\\x51Ay4 \\x2b WN\\x6a7 + COz + \\x52a +\\x20(function BIy1(){r\\x65turn YVd;}()" ascii
    $s17 = "47v + \\x46t + Pz);\\r\\nvar RJp2=\\x4dz + Ok + CLc9 + Tc \\x2b S\\x4dz9 + (function L\\x6d9(){ret\\x75rn TS\\x781;}());\\r\\nva" ascii
    $s18 = " \"gt\" + \"\";\\r\\nvar FOp3 = \\x22'+''+'len\" + \"\";\\r\\x0a\\x66unction Zb1\\x28CZq){return CZq;};var Pa1 = \"l\" + \"\";" ascii
    $s19 = "00;\\r\\n}\\r\\nreturn \\x28n\\x20\\x3e>> 0\\x29\\x20* \\x32.328306436538696\\x33e-10;\\r\\n} else \\x6e = 0xefc82\\x349d;\\r\\n" ascii
    $s20 = ";\\r\\x0avar Vh =\\x20\"\\x74h\" + \"\";\\r\\nva\\x72 WKb = \"len\\x67\" +\\x20\"\";\\r\\nfunctio\\x6e S\\x75\\x28SHv4){return S" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}