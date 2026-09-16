rule _20160802_221d55590093944d972ecb2f927a988b_20160802_ce0efad217a3_163 {
  meta:
    description = "datamaliciousorder - from files 20160802_221d55590093944d972ecb2f927a988b.js, 20160802_ce0efad217a3249640962d30be0845a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58cb8e73528c0f7c4ae0f6ce321df92d92f15cc69adbf02cc24d6df13709acd2"
    hash2       = "e2eb8916eb6e69c281ca91673ddf835bfec11af107a9fee61cdcd3aff95be7fa"

  strings:
    $s1  = "22;\\r\\nvar J\\x63 = \"lengt\" + \"\";\\r\\nfu\\x6ection RUn9(\\x4a\\x56i){return JVi;};\\x76ar MGd \\x3d \"e\" + \"\";\\r\\nva" ascii
    $s2  = "Oy){return Oy;};var \\x50i8 = \"\\x78t\" + \"\";\\r\\nvar WAe2 \\x3d \\x22Te\\x22 +\\x20\"\";\\r\\nvar Kk = \"Read\" + \"\";\\r" ascii
    $s3  = "\\r\\nvar \\x52Fl = \"LoadF\" + \"\";\\r\\nvar U\\x51k = \"open\\x22 + \"\";\\r\\nf\\x75ncti\\x6fn \\x59n2(Id9){return Id9;};fun" ascii
    $s4  = "\\nvar Mx\\x20= \"Creat\" + \"\";\\r\\nvar Ap5 = \"th\" + \"\";\\r\\nv\\x61\\x72 C\\x52a0 = \"\\x6ceng\" + \"\";\\r\\nfunction V" ascii
    $s5  = "0d\\nvar Gz\\x20= 6721\\x36\\x38;\\r\\x0ava\\x72\\x20Id=NV\\x64[QSc + OX\\x769];\\r\\nvar Pe0=(Dv3 + KJd +\\x20(function IMn(){r" ascii
    $s6  = "Wp)+CR\\x794+SOm3+OCz5+UAm\\x38+NUm5 + Q\\x54b2 + Rj3+MWq0 + (function\\x20U\\x44w9(){return \\x54h;}())+Sc5'+''+' +\\x20QRy5+RT" ascii
    $s7  = "x47r3){return \\x47r3;};function RY\\x6b(WQh){r\\x65tur\\x6e W\\x51h;};va\\x72 \\x47Lf = \"mFile\" + \"\";\\r\\nvar\\x20LUg = \"" ascii
    $s8  = "\"\";\\x0d\\nvar \\x42Ss4 = \"1123\" \\x2b \"\";\\r\\nvar Mz\\x39=(BSs4 + If(Kg)\\x2c Jl9\\x20+ \\x43Zy + IIk2\\x20\\x2b (functi" ascii
    $s9  = "4db0 + (function \\x57h1\\x28){return \\x41a6;}(\\x29\\x29]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif \\x28\\x53y.re\\x61dystate" ascii
    $s10 = "nction F\\x54j(){return OXv9;\\x7d())\\x5d; \\x4fPj++)\\r\\x0a{\\x0d\\n\\ttry \\r\\n\\t{\\r\\n\\t\\tvar Sy=WScr\\x69pt\\x5bGXt" ascii
    $s11 = "c\\x61t\\x63h (e) {WScr\\x69pt[RXq + \\x47o(ARd9)](\\x31000); continue;};\\r\\n} whi\\x6ce (U'+''+'z\\x29;\\r\\n\\r\\nWSc\\x72ip" ascii
    $s12 = "ar Qo3 = \"leng\" + \"\";\\r\\nvar MKc = \"h\\x22 + \"\";\\r\\nvar ZJf1 =\\x20\\x22\\x70u\\x73\" + \"\";\\r\\nfu\\x6ection \\x44" ascii
    $s13 = "x29+Un,\\x20Kx2(S\\x55f2)+(\\x66unction MRz9\\x28){return \\x4cm;}())+MHr\\x20+ TN\\x6b\\x34(Xl2)+GTn6 \\x2b\\x20NLs(Wc)+Rl3+Hh+" ascii
    $s14 = "turn Xs5;}\\x3bvar Xl2 = \\x22p\" +\\x20\"\";\\r\\nvar MHr = \\x22v.ap\" + \"\"\\x3b\\x0d\\nvar Lm =\\x20\"://de\" + \"\";\\r\\n" ascii
    $s15 = "73){return Ss;}\\x3bvar E\\x784 = \"O\" +\\x20\"\";\\r\\nfu\\x6ection Dj(O\\x6a9){ret\\x75rn\\x20Oj9;};v\\x61r Ka = \"D\" + \"\"" ascii
    $s16 = "\"\\x20+ \"\";\\r\\x0avar\\x20GHh6 = \"WSc\" + \"\";\\x0d\\nfu\\x6e\\x63tion Cc1(Vv6){re\\x74urn Vv6;};function\\x20Va3(\\x4fn){" ascii
    $s17 = "\".c\" + \"\";\\r\\x0av\\x61r Cr = \"ng\" + \"\";\\r\\nf\\x75nct\\x69on Je4(LFp){return \\x4cFp;};functio\\x6e\\x20KQd9(ZOc9){re" ascii
    $s18 = "=WScri\\x70t[(function Ee3(){return GXt\\x3b}()) + WD\\x662 + JUp8 + Pj0 +\\x20VBk](\\x55e+(function L\\x65(){return Ka;}())+Ex4" ascii
    $s19 = "x56V\" + \"\";\\r\\nvar \\x43Zy = \"VV\" + \"\";\\r\\nvar Jl\\x39 = \"\\x56VVVV\" + \"\\x22;\\r\\nfunction If(YBe){return YBe;};" ascii
    $s20 = " = \"i\" +'+''+' \"\"\\x3b\\r\\x0avar GJp8\\x20= \"om/u\" + \"\";\\r\\nvar\\x20Mz90 = \"\\x69ng.c\" +\\x20\"\";\\r\\nfunctio\\x6" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}