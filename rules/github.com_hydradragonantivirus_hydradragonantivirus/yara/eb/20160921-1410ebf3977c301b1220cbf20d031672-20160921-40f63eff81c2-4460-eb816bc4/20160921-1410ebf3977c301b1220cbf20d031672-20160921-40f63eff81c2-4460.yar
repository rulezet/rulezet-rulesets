rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_40f63eff81c2_4460 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash3       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"

  strings:
    $s1 = "rn \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s2 = " \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s3 = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s4 = "d\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s5 = "(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}