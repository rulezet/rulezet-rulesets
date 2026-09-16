rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_b6523fd99592_5231 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"

  strings:
    $s1 = "{return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";}" ascii
    $s2 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s3 = "return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})" ascii
    $s4 = "{return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"Ug\";})" ascii
    $s5 = "\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}