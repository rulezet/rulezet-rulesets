rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_e24d9e7aa16c_5434 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash3       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "\"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s2 = "eturn \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})()" ascii
    $s3 = "eturn \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(func" ascii
    $s5 = "rn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}