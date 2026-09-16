rule sig_20160831_025c0b826ec9ab0c41566848196433cb {
  meta:
    description = "datamaliciousorder - file 20160831_025c0b826ec9ab0c41566848196433cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8a2f6605cd0101bbc5df56e99a6d18cacbfc34a061f20bc1eb79073900dcdde"

  strings:
    $s1  = "aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s6  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s10 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s11 = "t-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s12 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Pw2shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s15 = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfuc" ascii
    $s17 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuc" ascii
    $s18 = "aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfuckin" ascii
    $s19 = "aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s20 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}