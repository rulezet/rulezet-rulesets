rule _20160921_78bd4256ddc0b384791a12e8ab1fd8a4_20160921_91734b00fd54_5421 {
  meta:
    description = "datamaliciousorder - from files 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s2 = "\"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retu" ascii
    $s4 = "b\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s5 = ",(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}