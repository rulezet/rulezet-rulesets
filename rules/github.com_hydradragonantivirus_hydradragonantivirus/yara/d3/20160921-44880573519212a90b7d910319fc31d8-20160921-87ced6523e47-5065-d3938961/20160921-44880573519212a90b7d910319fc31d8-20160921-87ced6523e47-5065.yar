rule _20160921_44880573519212a90b7d910319fc31d8_20160921_87ced6523e47_5065 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash4       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1 = "UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s2 = " \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(func" ascii
    $s3 = "on fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"X" ascii
    $s4 = "{return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})()" ascii
    $s5 = "uck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}