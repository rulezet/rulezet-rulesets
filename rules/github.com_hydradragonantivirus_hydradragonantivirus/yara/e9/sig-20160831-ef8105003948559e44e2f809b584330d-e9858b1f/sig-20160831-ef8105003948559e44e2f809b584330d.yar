rule sig_20160831_ef8105003948559e44e2f809b584330d {
  meta:
    description = "datamaliciousorder - file 20160831_ef8105003948559e44e2f809b584330d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24a8390c1388cf152815ba458476c55e0cf8fc394ec282784d38863c2536cba6"

  strings:
    $s1  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucki" ascii
    $s3  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii
    $s10 = "he-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s12 = "aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuc" ascii
    $s13 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s16 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuc" ascii
    $s17 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s18 = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}