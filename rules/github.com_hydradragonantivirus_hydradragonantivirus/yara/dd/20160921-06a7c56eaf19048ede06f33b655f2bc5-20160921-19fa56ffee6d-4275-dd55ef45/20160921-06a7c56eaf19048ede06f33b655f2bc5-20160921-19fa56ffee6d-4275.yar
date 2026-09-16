rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_19fa56ffee6d_4275 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "uck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Sx\"" ascii
    $s2 = ",(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){" ascii
    $s3 = "\"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s4 = "ck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb" ascii
    $s5 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}