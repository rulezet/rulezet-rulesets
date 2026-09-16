rule sig_20160831_2cbac10e155752d686decffbcaa7e3cf {
  meta:
    description = "datamaliciousorder - file 20160831_2cbac10e155752d686decffbcaa7e3cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaa2dec250a0632f1efefeece7037ddfeb969d1a494cd962b768dd2bc9231db7"

  strings:
    $s1  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s2  = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuc" ascii
    $s3  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking" ascii
    $s9  = "he-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s10 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s11 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Noshut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Noshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuckin" ascii
    $s16 = "aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuckin" ascii
    $s18 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}