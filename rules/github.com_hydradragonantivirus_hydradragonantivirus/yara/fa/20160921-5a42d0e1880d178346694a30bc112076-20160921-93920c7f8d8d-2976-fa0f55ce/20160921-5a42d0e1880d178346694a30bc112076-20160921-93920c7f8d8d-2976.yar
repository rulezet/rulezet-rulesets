rule _20160921_5a42d0e1880d178346694a30bc112076_20160921_93920c7f8d8d_2976 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s2 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s3 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s4 = "{return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s5 = "turn \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(" ascii
    $s6 = "urn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s7 = "n fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}