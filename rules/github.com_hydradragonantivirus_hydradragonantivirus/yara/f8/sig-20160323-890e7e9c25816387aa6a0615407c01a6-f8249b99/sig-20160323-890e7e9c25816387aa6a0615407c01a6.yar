rule sig_20160323_890e7e9c25816387aa6a0615407c01a6 {
  meta:
    description = "datamaliciousorder - file 20160323_890e7e9c25816387aa6a0615407c01a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c925fdf3a6f93e206f2c1dcd1eebfa4e37231de6870c9fcaebfe5701e943ae1f"

  strings:
    $s1  = "return WScript.CreateObject(fGyBK);" fullword ascii
    $s2  = "var Bf = true  , Rwco = JxY[7] + JxY[9] + JxY[11];" fullword ascii
    $s3  = "return FSwvSyO[0] + FSwvSyO[2] + FSwvSyO[4] + \".F\" + FSwvSyO[7] + FSwvSyO[9] + FSwvSyO[12] + FSwvSyO[14];" fullword ascii
    $s4  = "var FSwvSyO = qtxAS(ZWQoigxnIV+\" \"+\"System RA LUXBX Obj DyHxJM ect FrAKOoS QHdJW\", \" \");" fullword ascii
    $s5  = "var JxY = (\"2.XMLHTTP WqSqSHh keEEO XML ream St RuhlLwWs AD nCwcvVM O KCSJ D\").split(\" \");" fullword ascii
    $s6  = "qCSi.open(BaLaz,nvnEm,false);" fullword ascii
    $s7  = "function ysQW(fGyBK) {" fullword ascii
    $s8  = "return Utf.size;" fullword ascii
    $s9  = "function oxSv(txiXe) {" fullword ascii
    $s10 = "return ONLrLnn(vY,WvNYh[631-625]+WvNYh[533-526]+WvNYh[358-350]);" fullword ascii
    $s11 = "PWE = B; break; " fullword ascii
    $s12 = "function pKkhJtM(MUrL) {" fullword ascii
    $s13 = "function srGPp(KukoDy) {" fullword ascii
    $s14 = "function XTTu(vWcbS,njaij) {" fullword ascii
    $s15 = "return DxYMw;" fullword ascii
    $s16 = "function qtxAS(QDc,VmrWJ) {" fullword ascii
    $s17 = "return gYLqqu/*Nq38Z0YhUGh3blW19BQc8Ekpk*/.position=780-780;" fullword ascii
    $s18 = "return QDc.split(VmrWJ);" fullword ascii
    $s19 = "function wzti(gVfIT,nvnEm,BaLaz) {" fullword ascii
    $s20 = "if (P >= AQuzp.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}