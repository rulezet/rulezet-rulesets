rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_9e9f1aaa0e05_3509 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash3       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})" ascii
    $s2 = "eturn \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s3 = "ction fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "Nm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s5 = "ck(){return \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj" ascii
    $s6 = "(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}