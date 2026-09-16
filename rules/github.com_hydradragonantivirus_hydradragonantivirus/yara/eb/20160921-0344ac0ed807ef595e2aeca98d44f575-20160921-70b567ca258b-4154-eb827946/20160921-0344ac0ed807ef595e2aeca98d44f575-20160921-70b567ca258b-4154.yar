rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_70b567ca258b_4154 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "{return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})" ascii
    $s2 = "eturn \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "k(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe" ascii
    $s4 = "\"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s5 = " \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}