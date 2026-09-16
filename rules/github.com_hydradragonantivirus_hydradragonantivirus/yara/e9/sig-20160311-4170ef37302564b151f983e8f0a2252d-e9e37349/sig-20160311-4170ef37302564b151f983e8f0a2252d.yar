rule sig_20160311_4170ef37302564b151f983e8f0a2252d {
  meta:
    description = "datamaliciousorder - file 20160311_4170ef37302564b151f983e8f0a2252d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c5dd37064a785f6646921103c7dbbab4ba982ed1de922c50fa768a62188e36d"

  strings:
    $s1  = "return ymgEkZj[0] + ymgEkZj[2] + ymgEkZj[4] + \".F\" + ymgEkZj[7] + ymgEkZj[9] + ymgEkZj[12] + ymgEkZj[14];" fullword ascii
    $s2  = "var pB = true  , OfRU = ykH[7] + ykH[9] + ykH[11];" fullword ascii
    $s3  = "vbJND.open(QOKpE,SHype,false);" fullword ascii
    $s4  = "var ykH = (\"2.XMLHTTP XjYGCHY fSalC XML ream St CmHeblup AD LAmqLcX O HHci D\").split(\" \");" fullword ascii
    $s5  = "var ymgEkZj = \"Sc kVjRZwm r nTodaRfyZ ipting JqsOiPY kKX ile LTBpNxDeabMtlJ System bY hyjEr Obj PdLBGP ect ztsIbfU\".split(\" " ascii
    $s6  = "function PsEL(yMlGZ) {" fullword ascii
    $s7  = "return ojZdSLf" fullword ascii
    $s8  = "function vvJQPHyz(EjNoD,ZMrPVe) {" fullword ascii
    $s9  = "function tnYhkyD(qavA) {" fullword ascii
    $s10 = "function BVXN(lCbtk) {" fullword ascii
    $s11 = "return ZyooW.status;" fullword ascii
    $s12 = "function UHXK(JxpjO) {" fullword ascii
    $s13 = "function wdZVNKo(APWs,GDXwQ) {" fullword ascii
    $s14 = "function tIjXIeZF() {" fullword ascii
    $s15 = "function uSoA(kXIBF) {" fullword ascii
    $s16 = "function RIrL(uByNE) {" fullword ascii
    $s17 = "return wdZVNKo(oY,XqCLA[906-900]+XqCLA[694-687]+XqCLA[387-379]);" fullword ascii
    $s18 = "function HniL(ZyooW) {" fullword ascii
    $s19 = "function nrCi(DZXGX,gPSUk) {" fullword ascii
    $s20 = "if (FZLXk == 737-537){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}