rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_3272 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash4       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1 = "turn \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s3 = "eturn \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s4 = ";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fu" ascii
    $s5 = "nction fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s6 = " fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}