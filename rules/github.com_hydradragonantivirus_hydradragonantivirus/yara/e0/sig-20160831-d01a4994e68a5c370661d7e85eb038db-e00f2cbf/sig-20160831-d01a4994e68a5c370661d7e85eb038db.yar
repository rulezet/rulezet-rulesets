rule sig_20160831_d01a4994e68a5c370661d7e85eb038db {
  meta:
    description = "datamaliciousorder - file 20160831_d01a4994e68a5c370661d7e85eb038db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf8965b8efcba688661755622513f62d11967cc57bb49d48fd3e74eedfccae29"

  strings:
    $s1  = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuck" ascii
    $s2  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucki" ascii
    $s3  = "t-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s4  = "aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s9  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuckin" ascii
    $s10 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii
    $s11 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s13 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s14 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s17 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s19 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Lbshut-the-fuck-up-motherfucking" ascii
    $s20 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}