rule sig_20160405_baea244ade97ee3198c10ae1a10450b1 {
  meta:
    description = "datamaliciousorder - file 20160405_baea244ade97ee3198c10ae1a10450b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bfb00e13f3d5b2f20d20ae491487ac312c42a13f0c47a12b34e4e5009378d7c"

  strings:
    $s1  = "return aaUipPU[0] + aaUipPU[2] + aaUipPU[4] + \".F\" + aaUipPU[7] + aaUipPU[9] + aaUipPU[12] + aaUipPU[14];" fullword ascii
    $s2  = "var zi = true  , DQgm = EaE[7] + EaE[9] + EaE[11];" fullword ascii
    $s3  = "var EaE = (\"2.XMLHTTP yyuOewa Qbmqq XML ream St ikFvBvet AD iPEDTLe O bgxp D\").split(\" \");" fullword ascii
    $s4  = "YOhQ.open(Qvjaq,NCmAD,false);" fullword ascii
    $s5  = "function wHamhxO(qNeR) {" fullword ascii
    $s6  = "function QHPr(nPUbu,rMnTG) {" fullword ascii
    $s7  = "return WUS.size;" fullword ascii
    $s8  = "return kpcR;" fullword ascii
    $s9  = "return cuTUG.status;" fullword ascii
    $s10 = "return qLxSuDc;" fullword ascii
    $s11 = "if (J >= TuivS.length) {break;}" fullword ascii
    $s12 = "function PBDzR(sPOIecim,ZMDv) {" fullword ascii
    $s13 = "function rtJtx(kaJsWG) {" fullword ascii
    $s14 = "function pJylqBYcl(pyuQl) {" fullword ascii
    $s15 = "return cEiMZgm[0];" fullword ascii
    $s16 = "return \"TxwXUAgVUMJzFV\";" fullword ascii
    $s17 = "function rDosCS(ATsZPJB) {" fullword ascii
    $s18 = "return qNeR[GYNvwY[0]];" fullword ascii
    $s19 = "var HPXbLAV = \"MLnaTJ*fRE*pt.S\"+\"hell*enuFImt*Scri*\";" fullword ascii
    $s20 = "return new ActiveXObject(DeHn);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}