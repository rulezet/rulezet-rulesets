rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_e354814fb086_3527 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2 = "return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s3 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"M" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retur" ascii
    $s5 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii
    $s6 = "(){return \"Ai\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}