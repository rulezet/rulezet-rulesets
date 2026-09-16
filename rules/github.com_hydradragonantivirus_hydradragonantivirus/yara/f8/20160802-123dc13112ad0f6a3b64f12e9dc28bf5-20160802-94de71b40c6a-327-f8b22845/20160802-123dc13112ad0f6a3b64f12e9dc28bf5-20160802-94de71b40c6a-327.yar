rule _20160802_123dc13112ad0f6a3b64f12e9dc28bf5_20160802_94de71b40c6a_327 {
  meta:
    description = "datamaliciousorder - from files 20160802_123dc13112ad0f6a3b64f12e9dc28bf5.js, 20160802_94de71b40c6a5884c90d612e53d0c91a.js, 20160802_c4df9b0da46ef4ba68831652b1dab99e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c2033533d44cc14b45bab6eecd5231e291e45124d068ad1bb8da0b132dc8b5"
    hash2       = "31ce36c077b7274e101a682d48e4a108d0a53f3a3e6c13dc3dc93fdc21a11365"
    hash3       = "759873097f4e07bfc5361255ef51a8a7aa1734d091fcb34b31a6f7ad71274ac9"

  strings:
    $s1  = "(){return\\x20Gr4;}()) + (function Ii\\x28){re\\x74urn TEd;}\\x28)) + Zf+Hh+VUg + RUf+Cp + IHt];\\r\\nvar Ba5=WScript\\x5bNMh(" ascii
    $s2  = "0ARt\\x3dWScript[(fun\\x63tion Wc(){return ZOc9;}()) + Wc6 + DAz1](TYj+Mf(Cc0)+Wt\\x36+XOs + Yv + Xp6(\\x58f));\\r\\n\\t\\tARt[Z" ascii
    $s3  = "000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.3283064365\\x3386963e-10;\\r\\n\\x7d else n = 0\\x78efc82\\x34\\x39d;\\r\\n};\\r\\nreturn " ascii
    $s4  = "funct\\x69on LBy\\x28){return OXv9;}())];'+''+'\\x0d\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r\\nv\\x61r\\x20Ya=360\\x37 - \\x33605" ascii
    $s5  = "ew Array();\\r\\n\\tfor (var OP\\x6a=6938 -\\x20\\x36938; OPj < Tf0[JQu(Q\\x53c\\x29\\x20+ (function \\x43n2(){return OX\\x769;}" ascii
    $s6  = "6e IDj;}()) + Oj9);\\r\\n\\t\\tbreak;\\r\\n\\t}\\r\\n\\tcatch (e\\x29 {WScript[DM\\x61 + DTf1](1000\\x29; continue;};\\r\\n} whi" ascii
    $s7  = "\\x44Hf1[OPj]\\x29 %\\x200x10000\\x300\\x300;\\r\\x0a\\t};\\r\\n\\tif (REt2 != Cm) {return [];};\\r\\n\\t\\r\\n\\treturn DHf1 /*" ascii
    $s8  = "\\x0avar Pe0=(Dv3 + KJd + (functi\\x6fn IMn(){return CZi8;}\\x28\\x29\\x29, Zs5 + Te1 + Su(MSl) + Xt6);\\r\\nvar UWy4=Pe0[Q\\x53" ascii
    $s9  = "r\\nv\\x61r Pe=[\\x46g\\x31 \\x2b KL\\x64(JSw7) + Wg + (f\\x75n\\x63t\\x69on Xx4(){return ARk\\x32;}()) + QL\\x650 + GLo1, GUl(Q" ascii
    $s10 = "n true;}\\r\\n\\tels\\x65\\r\\n\\x09\\x09\\x7bretu\\x72n false;}\\r\\x0a};\\r\\n\\r\\n\\r\\nfunctio\\x6e\\x20KTb8 /* k\\x20 */" ascii
    $s11 = "d6){return Y\\x646\\x3b};\\x66unction Up(Wr6\\x29{retur\\x6e Wr6;};var DAz1 = \"\\x62\\x6aect\\x22 + \"\";\\x0d\\x0avar Wc6 = \"" ascii
    $s12 = "x20functio\\x6e( range ) {\\r\\nretu\\x72\\x6e\\x20Math.\\x66loor\\x28ran\\x67e * (rawprng() + (rawprng() \\x2a 0x\\x3200000 | 0" ascii
    $s13 = " + \\x43Oz + Ra + (function OMw8(){return YVd\\x3b}()) \\x2b QKv];\\r\\x0a\\r\\nfo\\x72 \\x28var OPj=0; OPj <\\x20P\\x65[QSc + (" ascii
    $s14 = ";\\r\\nvar Mz9=(BSs4 + If(Kg\\x29, Jl9 + CZy + \\x49Ik2\\x20+ (function NKy0(){return \\x45Yf;}\\x28)));\\r\\nv\\x61r Te=Mz9[QSc" ascii
    $s15 = "tion Ry0(){return Og6\\x3b}())+NAm9+MSc5 + QRy5+RTo\\x32(Lr8)+\\x55n+WRr1 + \\x5ax, SUf2+QEw+MHr +\\x20TNk4(Xl2)+(functi\\x6f\\x" ascii
    $s16 = "Zo7(Kr6) + \\x50j2;\\r\\n\\r\\nfunction uheprng() {return (function() {\\r\\nva\\x72 \\x6f = \\x348, c\\x20= 1, p = o, s =\\x20n" ascii
    $s17 = "63 *\\x20s[p] \\x2b c * \\x32.32830643653\\x386963e-10;\\x0d\\nreturn s[\\x70] = \\x74\\x20- (c = t | \\x30\\x29;\\r\\n}return r" ascii
    $s18 = "I\\x7a0 \\x3d \"%/\" + \"\";\\x0d\\nvar MBi = \"MP\\x22 + \"\";\\r\\nvar\\x20Ft = \"\\x25TE\" + \"\";\\r\\nfunction Rn(YD\\x784)" ascii
    $s19 = "\\x2b (function Ca\\x28){return Wc6\\x3b}()) + DAz1](DW\\x628 + \\x53Sq\\x20+ Rn(VVl7\\x29\\x20+ MEp9);\\r\\nvar M\\x7a\\x3dBa5." ascii
    $s20 = "\\x0d\\n\\r\\n\\x66unction Mas\\x68() {\\x0d\\nvar n = 0xefc8249d;\\r\\n\\x76ar mash = function(dat\\x61) {\\r\\nif ( data ) {" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}