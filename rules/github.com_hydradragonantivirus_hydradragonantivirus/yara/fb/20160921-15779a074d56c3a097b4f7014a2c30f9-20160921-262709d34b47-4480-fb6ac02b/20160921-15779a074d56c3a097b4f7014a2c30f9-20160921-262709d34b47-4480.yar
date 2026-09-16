rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_262709d34b47_4480 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash3       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1 = "eturn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})()" ascii
    $s2 = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function " ascii
    $s3 = "nction fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s4 = "{return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})()," ascii
    $s5 = "n fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJ" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}