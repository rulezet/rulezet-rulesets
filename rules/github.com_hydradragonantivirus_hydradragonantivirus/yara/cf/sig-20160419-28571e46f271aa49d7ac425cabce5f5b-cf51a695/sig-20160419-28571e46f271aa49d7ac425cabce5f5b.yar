rule sig_20160419_28571e46f271aa49d7ac425cabce5f5b {
  meta:
    description = "datamaliciousorder - file 20160419_28571e46f271aa49d7ac425cabce5f5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36b5d539e58c9519d340beda8405ed3384ef2f6c13e6cef9ef77c5775865a333"

  strings:
    $s1  = "return QZJkKpR[0] + QZJkKpR[2] + QZJkKpR[4] + \".F\" + QZJkKpR[7] + QZJkKpR[9] + QZJkKpR[12] + QZJkKpR[14];" fullword ascii
    $s2  = "var KV = true  , Meip = BTj[7] + BTj[9] + BTj[11];" fullword ascii
    $s3  = "var BTj = (\"2.XMLHTTP qXfOUkO MQkhU XML ream St MODciqhK AD HtZXqVw O qrGz D\").split(\" \");" fullword ascii
    $s4  = "Viys.open(nNZNN,QXfRb,false);" fullword ascii
    $s5  = "return qWyMLDS;" fullword ascii
    $s6  = "function ikFSW(tbpioTlE,Aoch) {" fullword ascii
    $s7  = "function jlqL(qgePf) {" fullword ascii
    $s8  = "return new ActiveXObject(MeWh);" fullword ascii
    $s9  = "return ywrrgcf[0];" fullword ascii
    $s10 = "function LxXozbv(ojwF,JjtIm) {" fullword ascii
    $s11 = "function kNhQYGYN(VdO) {" fullword ascii
    $s12 = "function bSau(JYJle) {" fullword ascii
    $s13 = "return nZg[mnFm[0]](fkWav);" fullword ascii
    $s14 = "function SPRQ(PVxxz) {" fullword ascii
    $s15 = "function kAUiEyp(pIES) {" fullword ascii
    $s16 = "function AhEA(VImrA,uFthB) {" fullword ascii
    $s17 = "function ezHqPJiq(Ocsk) {" fullword ascii
    $s18 = "bMV = N; break; " fullword ascii
    $s19 = "if (S >= qgePf.length) {break;}" fullword ascii
    $s20 = "function NiFKX(ZIZiuC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}