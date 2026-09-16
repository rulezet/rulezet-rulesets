rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_50b14bf13c50_4898 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash3       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1 = ";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s2 = "turn \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(" ascii
    $s3 = "Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(functio" ascii
    $s4 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return" ascii
    $s5 = "tion fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}