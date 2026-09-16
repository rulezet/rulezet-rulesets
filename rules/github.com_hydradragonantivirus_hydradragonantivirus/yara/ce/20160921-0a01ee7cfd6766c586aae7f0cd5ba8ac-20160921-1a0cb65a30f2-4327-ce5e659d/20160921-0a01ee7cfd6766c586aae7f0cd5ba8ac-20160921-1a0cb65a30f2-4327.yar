rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_1a0cb65a30f2_4327 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1 = "){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})" ascii
    $s2 = "tion fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return" ascii
    $s3 = "Rn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(functio" ascii
    $s4 = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s5 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}