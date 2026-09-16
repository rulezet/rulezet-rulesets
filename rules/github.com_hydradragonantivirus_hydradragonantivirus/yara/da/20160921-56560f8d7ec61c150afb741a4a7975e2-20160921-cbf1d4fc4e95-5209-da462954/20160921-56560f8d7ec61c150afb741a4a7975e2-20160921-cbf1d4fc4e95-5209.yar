rule _20160921_56560f8d7ec61c150afb741a4a7975e2_20160921_cbf1d4fc4e95_5209 {
  meta:
    description = "datamaliciousorder - from files 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash2       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"
    hash3       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "k(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";" ascii
    $s2 = "\"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s3 = "nction fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";}" ascii
    $s5 = "r\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}