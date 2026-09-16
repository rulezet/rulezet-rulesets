rule _20160802_6f8a3b3943ecf61763c5cd034903a47d_20160802_bbe19f018fdf_461 {
  meta:
    description = "datamaliciousorder - from files 20160802_6f8a3b3943ecf61763c5cd034903a47d.js, 20160802_bbe19f018fdffe668a3aae64b421f965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c33ba1bf78e59749625f33f9e1c7655dbc435674e25ca3599b97972646230e4"
    hash2       = "25bbec6f1a437208625ba7b78d87fae5bafdfb17a9ecc55a647cc7d589f3ea48"

  strings:
    $s1  = "x48f1 /* k  \\x2a/)\\r\\n\\x7b\\r\\n  \\x20 var\\x20W\\x48\\x790=WScript\\x5b(function Wc0(){return VUg;}\\x28\\x29) + R\\x55f +" ascii
    $s2  = "w0](1000'+''+'); continue;};\\r\\n} \\x77hile (Uz\\x29;\\r\\x0a\\r\\nWScript.Quit(0);\\r\\n\\r\\nfunc\\x74ion BKw(\\x44H\\x66\\x" ascii
    $s3  = "eturn s\\x5bp] \\x3d t - (c = t\\x20| 0)\\x3b\\r\\n}return random;}());\\x7d;\\r\\n\\r\\nfunction Mash() {\\x0d\\nvar n = 0xefc8" ascii
    $s4  = "n \\x4aYj5(){return IDj;}()) + Oj9);\\r\\n\\t\\tbreak;\\r\\n\\t\\x7d\\r\\n\\tcatch (e)\\x20{WScript[(fun\\x63tion Ut(){return TP" ascii
    $s5  = "\\x7bretur\\x6e RUf;}()) + (\\x66unction XEd0\\x28){return Je4;}(\\x29)](F\\x65 +\\x20JHu8 + Ot\\x38\\x20+ DWb8 + SSq);\\r\\x0a" ascii
    $s6  = "\\x28function Ii(){\\x72eturn NLs;}()) + RGl2+H\\x68];\\r\\n\\x76ar Ba5=WS\\x63ript[(function VEd(){return VUg;}()) + (function" ascii
    $s7  = "\\x2b (fu\\x6ection IMn(){return CZi8;}())\\x2c Zs5 + Te1 + Su(MSl) \\x2b\\x20\\x58t6);\\r\\nvar UWy4=Pe0[QSc + (function LBy(){" ascii
    $s8  = "{return LKf6\\x3b}()) + Lf7 + Bq1 + GWy + Xx4, SNt0 + \\x5am + N\\x776(Bw0) \\x2b Dy]\\x3b\\r\\x0a\\r\\nfor (var OPj=0\\x3b \\x4" ascii
    $s9  = "ar WKb = \"leng\" +\\x20\"\"\\x3b\\r\\nfunction \\x53u(S\\x48\\x764){return SHv\\x34;}\\x3bvar Xt6 = \"ll\" + \"\";\\r\\nvar MSl" ascii
    $s10 = "return AZx0;}()) \\x2b Kq + SUm + Jl + ZYi;\\r\\nvar RCn=RJp2 + TAf1 + Tz3;\\r\\n\\x0d\\n\\x66unc\\x74ion \\x75heprng() {retur" ascii
    $s11 = "+\\x20\"\";\\r\\nfuncti\\x6fn BZb(YSa){ret\\x75rn YSa;};fu\\x6ection \\x50Mq2(Qx){return Qx;};var K\\x68 = \"MP%/\" + \"\";\\r" ascii
    $s12 = "n\\x76ar EGw\\x20= \"ll\\x22 + \"\";\\r\\nv\\x61r Mj = \"lll\\x6cl\\x22 + \"\"\\x3b\\r\\n\\x66unction Oq\\x28Pf\\x30){\\x72eturn" ascii
    $s13 = "n} \\x65lse n \\x3d \\x30x\\x65fc8\\x3249d;\\r\\n};\\r\\nreturn\\x20m\\x61s\\x68;\\r\\n}\\r\\n\\r\\nvar Pe=[Mu0\\x20+ VOn + JI" ascii
    $s14 = "20RUf + Je4](TYj+(function \\x47i\\x32\\x28\\x29{return \\x43\\x630;}())+Wt6+XO\\x73 + Yv \\x2b\\x20Xf);\\r\\n \\x20  WHy0[L\\x4" ascii
    $s15 = "r Fe \\x3d \\x22WS\\x63r\" + \"\";\\r\\nfunc\\x74ion NM\\x68(Yd6){return Yd6;};\\x76\\x61r J\\x654 = \"b\\x6a\\x65ct\" + \"\";" ascii
    $s16 = "g]);\\r\\n\\t\\tARt[MPk5\\x20+\\x20WHy5 + Go(HXi6)]=1 \\x2a 0;\\r\\n\\t\\x09\\x41Rt\\x5bHs2 + \\x41Fy(Sa\\x30) \\x2b (functio\\x" ascii
    $s17 = ";\\r\\nfunct\\x69o\\x6e If(Y\\x42e){return YBe;};\\x76ar Kg\\x20= \"132\" + \\x22\"\\x3b\\r\\n\\x76ar BSs4 = \"1123\" + \"\";\\r" ascii
    $s18 = "9 \\x2b TQa7+Kg3+QRy5 + ZZs+Aw,\\x20Kx2(SUf2)+Un+Cl8+Ae+Yy1 +\\x20Ri5+(f\\x75nction Xl\\x32(){return Dt6;}()\\x29+Oj2+Xs5 + Lq3+" ascii
    $s19 = "E\\x52b=[SUf\\x32+DFm0+\\x56m+(funct\\x69on Zq9(){return N\\x6c;}())+Wn1+RWi+Po+Cy5 + Nn5+YTe1, NUm5+Ah+\\x55y3\\x20+ Oz7+\\x55" ascii
    $s20 = "1[0]== 0x4D && \\x44Hf\\x31\\x5b\\x31]== \\x30x5a)\\r\\n\\t\\t{r\\x65turn true;}\\r\\n\\te\\x6c\\x73e\\r\\n\\t\\t{ret\\x75rn \\x" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}