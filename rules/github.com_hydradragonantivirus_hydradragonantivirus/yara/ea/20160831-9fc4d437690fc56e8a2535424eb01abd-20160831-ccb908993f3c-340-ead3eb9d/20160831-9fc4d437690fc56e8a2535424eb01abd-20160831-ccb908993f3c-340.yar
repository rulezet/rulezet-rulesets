rule _20160831_9fc4d437690fc56e8a2535424eb01abd_20160831_ccb908993f3c_340 {
  meta:
    description = "datamaliciousorder - from files 20160831_9fc4d437690fc56e8a2535424eb01abd.js, 20160831_ccb908993f3c610bdaa2a9b3b5cf706b.js, 20160831_d274af2ec2a2e4517684e428dfe19003.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc5c048d7c46e026ee8e809e7b892cad91fafd0042c3992129d0a66a4d436a50"
    hash2       = "d6e4a7b5c1caa814b14af7ad6493a116e99314e38200f63fdb37d5449123fd0a"
    hash3       = "4d5fa9c9c0a5df85fc4866267cf31783083045a03583583c94df22955303b5de"

  strings:
    $s1 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfucki" ascii
    $s2 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuckin" ascii
    $s3 = "-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s4 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s5 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherf" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}