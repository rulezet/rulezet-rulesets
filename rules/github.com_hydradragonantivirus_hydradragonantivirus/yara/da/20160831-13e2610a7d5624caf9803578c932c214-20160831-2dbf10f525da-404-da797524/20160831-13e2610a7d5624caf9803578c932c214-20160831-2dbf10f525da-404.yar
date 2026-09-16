rule _20160831_13e2610a7d5624caf9803578c932c214_20160831_2dbf10f525da_404 {
  meta:
    description = "datamaliciousorder - from files 20160831_13e2610a7d5624caf9803578c932c214.js, 20160831_2dbf10f525da08ee49d8e97cb08b367b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1323588bc9b6357bfdc35a77bc12e81b83a1f5208a2a4807ddfbe6906416ef29"
    hash2       = "89444836e7d9e69647e3de63d4ff9dee852c923a2a97aed8965de830baef9b73"

  strings:
    $s1 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuck" ascii
    $s3 = "aver!!!!!!MQlshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucki" ascii
    $s4 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfuc" ascii
    $s5 = "-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s6 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfuckin" ascii
    $s7 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}