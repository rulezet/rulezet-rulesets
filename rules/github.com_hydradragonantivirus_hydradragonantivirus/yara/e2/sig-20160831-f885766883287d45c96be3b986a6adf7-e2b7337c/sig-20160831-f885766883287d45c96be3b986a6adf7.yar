rule sig_20160831_f885766883287d45c96be3b986a6adf7 {
  meta:
    description = "datamaliciousorder - file 20160831_f885766883287d45c96be3b986a6adf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5b4e4e90ff9279c54e8bd007a0e4e325ac6f44301ec0071cad3768ce7d0f4a0"

  strings:
    $s1  = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s4  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s6  = "he-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s7  = "aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s8  = "the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s9  = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s11 = "-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s12 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s17 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}