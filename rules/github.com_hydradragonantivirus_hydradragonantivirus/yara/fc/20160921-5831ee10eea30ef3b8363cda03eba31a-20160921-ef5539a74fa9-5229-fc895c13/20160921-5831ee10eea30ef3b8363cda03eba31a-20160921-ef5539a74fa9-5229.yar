rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_ef5539a74fa9_5229 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s2 = "return \"Wo0\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s3 = "ion fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s4 = "Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5 = "})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}