rule _20160921_9e9f1aaa0e051c856253652c93b64496_20160921_f156e377f521_5592 {
  meta:
    description = "datamaliciousorder - from files 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash2       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(functi" ascii
    $s2 = "v\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s3 = "k(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";" ascii
    $s4 = "\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s5 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}