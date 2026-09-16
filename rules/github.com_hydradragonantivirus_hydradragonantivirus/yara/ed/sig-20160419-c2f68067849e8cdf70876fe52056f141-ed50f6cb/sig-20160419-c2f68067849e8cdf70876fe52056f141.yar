rule sig_20160419_c2f68067849e8cdf70876fe52056f141 {
  meta:
    description = "datamaliciousorder - file 20160419_c2f68067849e8cdf70876fe52056f141.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daef7c7cb03c751aaac295feaad36befaa561657d842bcb43314d312ee77060e"

  strings:
    $s1  = "var wl = true  , hmRD = Pns[7] + Pns[9] + Pns[11];" fullword ascii
    $s2  = "return JJzleyM[0] + JJzleyM[2] + JJzleyM[4] + \".F\" + JJzleyM[7] + JJzleyM[9] + JJzleyM[12] + JJzleyM[14];" fullword ascii
    $s3  = "var Pns = (\"2.XMLHTTP CdFzzCv mrxpo XML ream St LivOBlix AD xWaIoqk O fEFQ D\").split(\" \");" fullword ascii
    $s4  = "csSV.open(SKDkZ,pvZQs,false);" fullword ascii
    $s5  = "function CoStkV(ASTV,zofrTS) {" fullword ascii
    $s6  = "if(O>=C.length) {break;}" fullword ascii
    $s7  = "function MOQr(NECTe) {" fullword ascii
    $s8  = "function bpfu(wQhEF,VmQht) {" fullword ascii
    $s9  = "function nxKJBZm(haGH) {" fullword ascii
    $s10 = "return new ActiveXObject(xMpV);" fullword ascii
    $s11 = "return MCH.size;" fullword ascii
    $s12 = "function AEAf(aqJBw) {" fullword ascii
    $s13 = "return JKIeh;" fullword ascii
    $s14 = "function cEZP(wPZIi) {" fullword ascii
    $s15 = "return haGH[eBYrEiV[0]+eBYrEiV[1]];" fullword ascii
    $s16 = "function qpBmBhcY(cvIg) {" fullword ascii
    $s17 = "function xHpblz(VhORpcR) {" fullword ascii
    $s18 = "function XpcfI(YcF,IxxrU) {" fullword ascii
    $s19 = "return \"oiCUboMKmtmIxj\";" fullword ascii
    $s20 = "if (N >= tutIy.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}