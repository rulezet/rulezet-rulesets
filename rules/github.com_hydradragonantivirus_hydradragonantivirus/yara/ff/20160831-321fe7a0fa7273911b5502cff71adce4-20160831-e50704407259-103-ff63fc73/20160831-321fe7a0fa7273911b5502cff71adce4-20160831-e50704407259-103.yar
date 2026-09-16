rule _20160831_321fe7a0fa7273911b5502cff71adce4_20160831_e50704407259_103 {
  meta:
    description = "datamaliciousorder - from files 20160831_321fe7a0fa7273911b5502cff71adce4.js, 20160831_e507044072598c7e8b74123a7dad9979.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf4e07602c3c34b728c0f222b041588137cb25a1fb75aaab763fb9157bd7fb8"
    hash2       = "0d4cb45b06fa8ceeff0e2c86717c2768012b17a3a9d3ec90f382a6b65704a8cb"

  strings:
    $s1 = "aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Yi6shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s3 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuc" ascii
    $s4 = "aver!!!!!!XBhshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfuckin" ascii
    $s5 = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Eeshut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s7 = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuc" ascii
    $s8 = "aver!!!!!!ZVyshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s9 = "aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!IJdshut-the-fuck-up-motherfucking-aver!!!!!!BDx7shut-the-fuck-up-motherfu" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}