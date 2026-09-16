rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_15779a074d56_4287 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash3       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"

  strings:
    $s1 = "a\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s2 = "return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\"" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s5 = " \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}