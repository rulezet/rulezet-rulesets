rule sig_20160802_b6de4941d51cacaf46fda28850944955 {
  meta:
    description = "datamaliciousorder - file 20160802_b6de4941d51cacaf46fda28850944955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f660971ee6adcd397c393f863fc77a831815de8e23e6cdc20502769c5d4e87"

  strings:
    $s1  = "    var aRv1 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "=0; OPj < Pe[QSc + (funct\\x69on FTj(){return OXv9;}())]; OPj++)\\r\\n{\\x0d\\n\\ttry\\x20\\r\\n\\t{\\r\\n\\t\\x09var \\x53y\\x3" ascii
    $s3  = "continue;\\r\\n\\t\\t}\\r\\n\\t\\x09\\r\\n\\t\\tvar ARt=WScript[\\x4am\\x20+\\x20Fe + JHu8 +\\x20Ot8](Oa4(E\\x61)+JWz3+Tv6+E\\x7" ascii
    $s4  = "ncti\\x6f\\x6e VEd(){return \\x55f;}()) + (function Rz()\\x7bretu\\x72n Je4;}()\\x29+JFw(XEd0) + FJq+Bb5(GHx)+Hg];\\r\\nvar Ba5=" ascii
    $s5  = "f'+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nva" ascii
    $s6  = "55;\\x0d\\n\\t\\r\\n\\tvar\\x20HFz=new Array();\\r\\n\\tfor (var OPj=6\\x3938 - 69\\x33\\x38; OPj < Tf0[JQu(QSc)\\x20+\\x20\\x28" ascii
    $s7  = "ript[STs6 +\\x20(functio\\x6e C\\x4bv9(){return Ly0;}())](1000); continue;};\\r\\n\\x7d while (Uz);\\x0d\\n\\r\\nWScript.Qu\\x69" ascii
    $s8  = "\\x65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" +" ascii
    $s9  = "\\tARt\\x5b\\x4ds4\\x20+ (function Er8(){\\x72e\\x74urn VJk5;}()) + JGm\\x33](RJp2\\x2c\\x20Ya\\x29;\\r\\n\\t\\tA\\x52t[NAe\\x30" ascii
    $s10 = "\\x76\\x61r CRy4\\x20= \"eser\" + \"\"\\x3b\\r\\nfu\\x6ectio\\x6e GY\\x650(AJi3){return AJi3\\x3b};var ZWp \\x3d \"if\" \\x2b " ascii
    $s11 = "/pl\" + \"\";\\r\\nfunction\\x20J\\x46w(\\x4dh){return Mh;}\\x3bvar FJ\\x71 = \".ru\" + \"\";\\r\\nvar\\x20\\x58Ed0\\x20= \"ny\"" ascii
    $s12 = " Fe = \"a\\x74\" + \"\";\\r\\n\\x76a\\x72 Jm = \"Cre\" +\\x20\"\";\\r\\nvar Hg\\x20= \"8in\" + \"\";\\r\\nfunction\\x20Bb5(IJh){" ascii
    $s13 = " Sk + Wi2 + (function U\\x61(){ret\\x75r\\x6e \\x49Nw6\\x3b}()) + Wk9 + Es1\\x20+\\x20V\\x4fw, Ft + DQb + XEh];\\x0d\\n\\r\\nfor" ascii
    $s14 = "z4(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52V" ascii
    $s15 = "x2c Kx2(SU\\x662)+(function WJf(){retur\\x6e NJa;}())+SKi9 + IKv+Aq +\\x20HJj9+O\\x6a2 + Wb4+L\\x713, SUf2+Zf + Rl3(\\x42Iq5)+VU" ascii
    $s16 = "turn RU\\x6e9;}()) \\x2b JVi]\\x28ENo);\\x0d\\n\\t\\x7d\\x3b\\r\\n\\t\\r\\n\\t\\x72eturn HF\\x7a\\x3b\\r\\n};\\r\\n\\r\\n\\r\\nf" ascii
    $s17 = "\";\\x0d\\nva\\x72 SFh = \"i\" + \\x22\";\\r\\nfunction \\x45v8(XCn9){return XCn9;};v\\x61r Rw \\x3d \\x22b\" + \"\\x22;\\r\\nva" ascii
    $s18 = "n >>>\\x200)\\x20* 2.3283064365386963e-10;\\r\\n} else n = 0xefc8249d;\\x0d\\n};\\r\\nreturn \\x6dash;\\r\\n}\\r\\n\\r\\n\\x76ar" ascii
    $s19 = "\"\";\\r\\nva\\x72 Wv = \"EFGHI\" + \"\";\\x0d\\nvar XPd9 = \"ABCD\" + \"\";\\r\\nvar Xr4 = \"xe\" \\x2b\\x20\"\\x22;\\r\\nfunc" ascii
    $s20 = "(\\x5aWp)+\\x43Ry4+SO\\x6d3+OCz5\\x2bUAm8+NUm\\x35 + QTb2 + Rj3+MWq\\x30 + (function UDw9(){return Th;}())+Ev8(AN\\x78) \\x2b Rw" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}