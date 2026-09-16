rule _20160921_1664afae318573894e850f85ff412d64_20160921_468b13a80ecc_4499 {
  meta:
    description = "datamaliciousorder - from files 20160921_1664afae318573894e850f85ff412d64.js, 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash2       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash3       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1 = ",(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s2 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){re" ascii
    $s3 = "k(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s4 = "\"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s5 = "fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DR" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}