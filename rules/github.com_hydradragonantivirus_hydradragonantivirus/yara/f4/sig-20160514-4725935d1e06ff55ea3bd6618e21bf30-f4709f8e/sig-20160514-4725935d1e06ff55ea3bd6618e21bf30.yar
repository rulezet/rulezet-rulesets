rule sig_20160514_4725935d1e06ff55ea3bd6618e21bf30 {
  meta:
    description = "datamaliciousorder - file 20160514_4725935d1e06ff55ea3bd6618e21bf30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86bb21ec34c0a1c8d3b99e459ddc680d4ecd5135924702165b657ef6ffd05da6"

  strings:
    $s1  = "while (UShE < FcTOIxPu - (7911 - 7909)) {" fullword ascii
    $s2  = "return QHVVvIk;" fullword ascii
    $s3  = "return tgJhdQL;" fullword ascii
    $s4  = "function oESit(dfegg) {" fullword ascii
    $s5  = "if (oWO == true) {" fullword ascii
    $s6  = "return iCfX;" fullword ascii
    $s7  = "return CRvl;" fullword ascii
    $s8  = "function DYX() {" fullword ascii
    $s9  = "return Hbagfz;" fullword ascii
    $s10 = "function dPt() {" fullword ascii
    $s11 = "function iyN() {" fullword ascii
    $s12 = "function QQecBUQ(nQPBr, HzjRNCKu) {" fullword ascii
    $s13 = "switch (\"pFChaU\") {" fullword ascii
    $s14 = "function jfdNDC() {" fullword ascii
    $s15 = "function mtYGPk() {" fullword ascii
    $s16 = "function CFw() {" fullword ascii
    $s17 = "function UdQGx() {" fullword ascii
    $s18 = "function Ynt() {" fullword ascii
    $s19 = "return bTUecg;" fullword ascii
    $s20 = "return HDgwIp;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}