rule _20160921_65ff2a70ce98d58243fbbdf4849b9c40_20160921_9b04118eed50_5326 {
  meta:
    description = "datamaliciousorder - from files 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash2       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash3       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "k(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\"" ascii
    $s2 = " \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(func" ascii
    $s3 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){" ascii
    $s4 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){ret" ascii
    $s5 = "(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}