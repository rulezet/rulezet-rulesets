rule _20160831_03b9cf5cd7da8848d6ca5bd2d98478f4_20160831_f0ef82afe500_91 {
  meta:
    description = "datamaliciousorder - from files 20160831_03b9cf5cd7da8848d6ca5bd2d98478f4.js, 20160831_f0ef82afe500053f8a36a7660b4bd887.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a16c695b98192e2fc5fd160d602a28715a3312c31d1bd9b54cada15c0ad45cc"
    hash2       = "15cc079df29a4ecdab24d5c645a94563adc2d4ba418cb28dd287c439a3a4838f"

  strings:
    $s1 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s7 = "aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfuckin" ascii
    $s8 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}