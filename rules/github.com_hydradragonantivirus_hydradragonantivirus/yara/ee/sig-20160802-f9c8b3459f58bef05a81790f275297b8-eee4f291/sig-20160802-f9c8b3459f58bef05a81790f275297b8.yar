rule sig_20160802_f9c8b3459f58bef05a81790f275297b8 {
  meta:
    description = "datamaliciousorder - file 20160802_f9c8b3459f58bef05a81790f275297b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "437ff2da5cf2e50159576390253ce51c8548f3f46541dd95ca06ef298b280a7b"

  strings:
    $s1  = "    var aJCi4 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "\\r\\n\\t\\t\\r\\n\\t\\tif (Sy.rea\\x64ys\\x74\\x61te < (\\x2d19\\x315 +\\x201919)) \\r\\n\\t\\t{\\r\\n\\t\\t\\tWScript[(func\\x" ascii
    $s3  = "n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nreturn (\\x6e >>> 0) * 2.\\x3328306436538\\x36963e-\\x31\\x30;\\r\\n} else n = 0xefc82" ascii
    $s4  = "\\x3d \"\\x63l\" + \"'+''+'\\x22;\\r\\nfun\\x63\\x74ion WPa(Vk){return Vk;};var BLy1\\x20\\x3d \"Text\" + \"\";\\r\\nvar TNr1 =" ascii
    $s5  = "9\\r\\x0a\\tva\\x72\\x20\\x48Fz=new Array();\\r\\n\\tfor\\x20(var\\x20OPj\\x3d6938 - 6938; OPj < Tf0\\x5bJQu(QSc) + (fu\\x6ectio" ascii
    $s6  = "t{return false;}\\r\\n}\\x3b\\r\\x0a\\x0d\\n\\r\\nfunctio\\x6e KT\\x628 /* L  */(E\\x63)\\r\\n{\\r\\n\\x20   v\\x61r WHy0=WScrip" ascii
    $s7  = "\\n\\t\\t\\x09}\\r\\n\\t\\t\\tSy[Pc0\\x5d(LEs7, ERb[O\\x45q6++ % \\x45Rb[\\x51Sc +\\x20OXv9\\x5d], false)\\x3b\\r\\x0a\\t\\t\\tS" ascii
    $s8  = "\\x38;}()), Zs5 + Te1 + Su(MSl) +\\x20Xt6);\\r\\nvar UWy4=Pe0[Q\\x53\\x63\\x20+ (function LBy(){return OXv9;}())];\\r\\n\\r\\nva" ascii
    $s9  = "n Kt;};functi\\x6fn Tl8(I\\x57s5){return IWs\\x35;};\\x76\\x61r\\x20Jc = \\x22e\" + \"\"\\x3b\\r\\nva\\x72 Oy = \"Cod\" + \"\";" ascii
    $s10 = " null\\x3b\\r\\nvar random = fu\\x6e\\x63\\x74ion( \\x72ange\\x20) {\\x0d\\nreturn Math.floor(range * (\\x72awp\\x72ng() + (rawp" ascii
    $s11 = "tARt[Tf5(Fy) + UW\\x783\\x20+ RVy(LWr) + ZVt7](\\x52Jp2, Y\\x61\\x29;\\r\\x0a\\t\\tARt[\\x50g3 + \\x58z4\\x5d();\\r\\n\\t\\r\\n" ascii
    $s12 = "9on VOy7(DHf1 /* L  *\\x2f)\\r\\n{\\r\\n\\ti\\x66 (\\x44Hf1[0]=\\x3d \\x30x4D\\x20&& DHf1[1]== 0x5a)\\r\\n\\t\\t{return true;}" ascii
    $s13 = " + Pa1);\\x0d\\x0avar Gz = 672168;\\r\\nvar Id=NVd[QSc + \\x4f\\x58v9\\x5d;\\r\\nvar Pe0=(Dv3 + KJd +\\x20(function IMn(){ret\\x" ascii
    $s14 = "n JQ\\x75(KKh4){return KKh4\\x3b};v\\x61r\\x20O\\x58\\x769 \\x3d\\x20\"gt\\x68\" + \"\"\\x3b\\r\\nvar QSc = \"l\\x65n\\x22 + \\x" ascii
    $s15 = "}())+Oj2+\\x47Tn6(DXs5)+(function Ii(\\x29{ret\\x75rn NLs;}(\\x29) + RGl2+Hh+UIk+(function VEd(){return Uf;}()) +\\x20(fun\\x63t" ascii
    $s16 = "){return \\x4bHz9;};var Nt0 = \\x225.1\" \\x2b \"\";\\r\\nvar YWl7 = \"t.\" + \"\";\\r\\x0avar Ki5\\x20=\\x20\"ques\" + \"\";\\x" ascii
    $s17 = "XML\"\\x20+ \"\";\\r\\nvar Sy8 = \"ML\" + \"\";\\r\\nvar IFc4 = \\x22\\x4dSX\\x22 + \"\";\\x0d\\nfunction QKv(Dq8){return Dq8;};" ascii
    $s18 = "x6ection Ft(MB\\x69){return MBi;}\\x3bvar Jm3 = \"\\x6c\" + \"\"\\x3b\\r\\nvar Jn9 = \"hel\" + \"\";\\r\\n\\x76ar Kh = \"pt.S\" " ascii
    $s19 = "\" + \"\";\\r\\nvar NLs = \"tor\" + \"\";\\r\\nfunction GTn6(Wc){return W\\x63;}\\x3bvar DXs5 = \"ina\" + \"\\x22\\x3b\\r\\nva" ascii
    $s20 = "Kv\\x28YWl7) + Zk(Nt0), IFc4 + Sy8 + IZl7 + \\x59v3(DQ\\x62)];\\r\\n\\r\\n\\x66or (\\x76a\\x72 OPj=0; OPj < Pe\\x5bQ\\x53c + (fu" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}