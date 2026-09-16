rule _20160831_97d20ea97caa1e84d9b9cf55ed4369eb_20160831_a39df2518d19_422 {
  meta:
    description = "datamaliciousorder - from files 20160831_97d20ea97caa1e84d9b9cf55ed4369eb.js, 20160831_a39df2518d1911aaa93e8c369273a09a.js, 20160831_e27f302bd7eab43216d00e804cbf5139.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c813b5524282a10ba1041434a0f0e82857317d424e19ad773a7a440bd32792"
    hash2       = "fea951ef1cfa30a63ad0a0a5417f3f9306aa494676ebe4bafcb6516129958f67"
    hash3       = "6c5380494e435105c080c5141e1391fc7906b54e33878fb68eb2b126f2c069e4"

  strings:
    $s1 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfuc" ascii
    $s5 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s7 = "aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s8 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}