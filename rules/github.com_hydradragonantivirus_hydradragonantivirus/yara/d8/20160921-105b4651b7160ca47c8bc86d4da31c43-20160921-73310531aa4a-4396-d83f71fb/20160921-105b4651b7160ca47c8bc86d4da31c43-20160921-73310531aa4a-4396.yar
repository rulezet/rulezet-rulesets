rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_73310531aa4a_4396 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"

  strings:
    $s1 = ")(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s2 = "return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s4 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}