rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_f156e377f521_3394 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"CCb\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s4 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"We\";})(),(function fuck(){re" ascii
    $s5 = "MIl\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii
    $s6 = "Wu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}