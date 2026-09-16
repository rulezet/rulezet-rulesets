rule sig_20160831_40ee47635b31237a88f307512fcd6892 {
  meta:
    description = "datamaliciousorder - file 20160831_40ee47635b31237a88f307512fcd6892.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08fe703628d99be98d2a5de470604fc972a777b59c983e25b174fc7dbcd4f3d6"

  strings:
    $s1  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfu" ascii
    $s4  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuck" ascii
    $s6  = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuck" ascii
    $s7  = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!HOx7shut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfuck" ascii
    $s11 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ue0shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking" ascii
    $s16 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s17 = "aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking" ascii
    $s20 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}