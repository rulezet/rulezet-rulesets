rule sig_20160831_b8e9a3c8b9d1e0667d9c98cf2f552b30 {
  meta:
    description = "datamaliciousorder - file 20160831_b8e9a3c8b9d1e0667d9c98cf2f552b30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "940e5c9f4fba2f0b16cfef4f2af563e431addac03bcd59c1ccc5cac41c2d3086"

  strings:
    $s1  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!LAo4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s13 = "-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s14 = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuc" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s17 = "t-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s18 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}