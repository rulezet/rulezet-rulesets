rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_ccb7f2594ec3_5446 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s2 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s3 = "turn \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s4 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s5 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}