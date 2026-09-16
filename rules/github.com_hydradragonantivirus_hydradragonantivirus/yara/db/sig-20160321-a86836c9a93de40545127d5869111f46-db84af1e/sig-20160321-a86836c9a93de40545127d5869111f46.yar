rule sig_20160321_a86836c9a93de40545127d5869111f46 {
  meta:
    description = "datamaliciousorder - file 20160321_a86836c9a93de40545127d5869111f46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "151520b46c80be8633953cf8db813e5450ff88281b47fc870f9f0b5435cb9613"

  strings:
    $s1  = "return WScript.CreateObject(OQVgS);" fullword ascii
    $s2  = "var Zy = true  , NilE = YIR[7] + YIR[9] + YIR[11];" fullword ascii
    $s3  = "return ZcRDDUT[0] + ZcRDDUT[2] + ZcRDDUT[4] + \".F\" + ZcRDDUT[7] + ZcRDDUT[9] + ZcRDDUT[12] + ZcRDDUT[14];" fullword ascii
    $s4  = "var ZcRDDUT = pawfT(ObGCVekQTs+\" \"+\"System gd TrCXm Obj kzMptn ect AUrUppL sLnXY\", \" \");" fullword ascii
    $s5  = "var YIR = (\"2.XMLHTTP myyXONR UqHqp XML ream St TTHEOXeP AD VkFNaiM O lzXx D\").split(\" \");" fullword ascii
    $s6  = "return wbzbf.status;" fullword ascii
    $s7  = "return czXbD;" fullword ascii
    $s8  = "function kOhQFLIw(nUE) {" fullword ascii
    $s9  = "return XILVUQ.position=562-562;" fullword ascii
    $s10 = "if(G>=j.length) {break;}" fullword ascii
    $s11 = "function IImOeBhfL(dLiAi) {" fullword ascii
    $s12 = "function ZhMw(wbzbf) {" fullword ascii
    $s13 = "return jDhG[KUNsoY[0]];" fullword ascii
    $s14 = "return czQjvZl(bk,YMYmn[610-604]+YMYmn[883-876]+YMYmn[305-297]);" fullword ascii
    $s15 = "return Uzm.split(jeTuv);" fullword ascii
    $s16 = "if (iPKEO > 158648-131){return true;} else {return false;}" fullword ascii
    $s17 = "function opgv(tkLuk,bsWbm) {" fullword ascii
    $s18 = "function OTWMJud(jDhG) {" fullword ascii
    $s19 = "function czQjvZl(THpN,DJTzi) {" fullword ascii
    $s20 = "function rGtw(kXuoU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}