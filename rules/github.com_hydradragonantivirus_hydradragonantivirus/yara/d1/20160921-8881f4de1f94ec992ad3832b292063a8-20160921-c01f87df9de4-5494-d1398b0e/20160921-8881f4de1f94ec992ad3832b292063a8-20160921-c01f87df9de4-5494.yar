rule _20160921_8881f4de1f94ec992ad3832b292063a8_20160921_c01f87df9de4_5494 {
  meta:
    description = "datamaliciousorder - from files 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\"" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s3 = "(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){" ascii
    $s4 = "{return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})()" ascii
    $s5 = "urn \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}