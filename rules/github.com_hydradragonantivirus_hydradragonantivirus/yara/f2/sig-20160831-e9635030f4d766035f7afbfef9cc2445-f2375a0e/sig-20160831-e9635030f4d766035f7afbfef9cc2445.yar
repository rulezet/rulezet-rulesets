rule sig_20160831_e9635030f4d766035f7afbfef9cc2445 {
  meta:
    description = "datamaliciousorder - file 20160831_e9635030f4d766035f7afbfef9cc2445.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8fbd54645caf8cf4c53f6d952c15d9b80669262b62e196cbfb13a9e4f9d3ca9"

  strings:
    $s1  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!ZVyshut-the-fuck-up-motherfuc" ascii
    $s4  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfu" ascii
    $s8  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuckin" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfuc" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucki" ascii
    $s16 = "-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s17 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking" ascii
    $s18 = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s20 = "the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}