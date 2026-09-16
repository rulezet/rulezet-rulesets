rule sig_20160831_41bd5b8b994df37ed097f53f534a2664 {
  meta:
    description = "datamaliciousorder - file 20160831_41bd5b8b994df37ed097f53f534a2664.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e64d2b688819041ac6c6348b8679e9a4406f57b2740d9099b8fe19c46a91d05"

  strings:
    $s1  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuc" ascii
    $s3  = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfuckin" ascii
    $s5  = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s7  = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfuckin" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuckin" ascii
    $s9  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfuc" ascii
    $s10 = "the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s16 = "-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s17 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii
    $s20 = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}