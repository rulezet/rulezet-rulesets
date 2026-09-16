rule sig_20160831_6ad320d7fe191fbe3fe6911c0c793264 {
  meta:
    description = "datamaliciousorder - file 20160831_6ad320d7fe191fbe3fe6911c0c793264.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c1da867d1ca67b4f8d46dcf34ca9faaa4c33fae7095aa28ccd8a06e53d5b89"

  strings:
    $s1  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s4  = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii
    $s9  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s14 = "the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s15 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s16 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Ncshut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}