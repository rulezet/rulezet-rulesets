rule _20160921_95c689d7ff4700a03d604b71aaf3634b_20160921_9e9f1aaa0e05_5559 {
  meta:
    description = "datamaliciousorder - from files 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash2       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"

  strings:
    $s1 = " \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Fv\";})(),(func" ascii
    $s2 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(funct" ascii
    $s3 = "function fuck(){return \"ZLd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4 = "k(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";" ascii
    $s5 = "(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}