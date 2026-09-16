rule _20160921_5e9244484429cd897ec88fe97140c29c_20160921_6db2cb585eb9_3827 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"

  strings:
    $s1 = " \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s2 = " \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "k(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";" ascii
    $s4 = "urn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s5 = "Ts\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s6 = "turn \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}