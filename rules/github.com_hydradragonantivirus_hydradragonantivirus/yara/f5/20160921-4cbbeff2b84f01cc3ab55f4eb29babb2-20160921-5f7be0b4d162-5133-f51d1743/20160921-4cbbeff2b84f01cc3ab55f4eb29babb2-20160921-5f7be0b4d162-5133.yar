rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_5f7be0b4d162_5133 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash4       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = " fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"M" ascii
    $s2 = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s3 = "turn \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})()" ascii
    $s4 = "\"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s5 = " \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}