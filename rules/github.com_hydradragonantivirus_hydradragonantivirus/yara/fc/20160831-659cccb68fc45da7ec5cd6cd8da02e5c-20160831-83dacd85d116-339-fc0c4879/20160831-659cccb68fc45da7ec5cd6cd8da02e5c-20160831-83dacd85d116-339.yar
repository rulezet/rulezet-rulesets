rule _20160831_659cccb68fc45da7ec5cd6cd8da02e5c_20160831_83dacd85d116_339 {
  meta:
    description = "datamaliciousorder - from files 20160831_659cccb68fc45da7ec5cd6cd8da02e5c.js, 20160831_83dacd85d1165a593f7d0c2a35f6ed9e.js, 20160831_b151b9ea4061229c67f340edfd370ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cdd65caa06f9fcf3ca28945410b66123b06a5d8a28fb6c5a98c5e7ee58d2e84"
    hash2       = "775ab81c367c9aadee5b0509ab5bd17d48400051db75b715a17b0b9e3e031e75"
    hash3       = "26e92ab7936c62ce714ee0d4d6fffb039dd9b74478dcb36bc84c73852fbe3c8f"

  strings:
    $s1 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfu" ascii
    $s2 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking" ascii
    $s4 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuckin" ascii
    $s5 = "aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!APzshut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}