rule _20160921_5230866e44eda4e054d929933fdfdae1_20160921_73310531aa4a_5169 {
  meta:
    description = "datamaliciousorder - from files 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash2       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"

  strings:
    $s1 = "(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s2 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(func" ascii
    $s3 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s4 = "n fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s5 = "eturn \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}