rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_18eedffe02de_3189 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash3       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash4       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"YAv\";})(),(" ascii
    $s2 = "(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck" ascii
    $s3 = "Xf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s4 = ";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s5 = " fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s6 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZW" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}