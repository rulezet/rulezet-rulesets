rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_ccb7f2594ec3_4464 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s2 = "turn \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s3 = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s4 = "n fuck(){return \"Tv\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s5 = "\"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}