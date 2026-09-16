rule sig_20160831_26d605201159b8fa95ad54cfd618c618 {
  meta:
    description = "datamaliciousorder - file 20160831_26d605201159b8fa95ad54cfd618c618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b87f4dfbec194f7d363dc8af6791c6a20de43216cea63b4e843b06e32a073a"

  strings:
    $s1  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfuck" ascii
    $s3  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfuc" ascii
    $s5  = "aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s6  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfuc" ascii
    $s8  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfuck" ascii
    $s14 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfuc" ascii
    $s16 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s19 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfuc" ascii
    $s20 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}