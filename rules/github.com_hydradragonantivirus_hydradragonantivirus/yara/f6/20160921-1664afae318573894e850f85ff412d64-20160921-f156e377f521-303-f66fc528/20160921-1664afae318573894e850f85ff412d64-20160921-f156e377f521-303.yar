rule _20160921_1664afae318573894e850f85ff412d64_20160921_f156e377f521_303 {
  meta:
    description = "datamaliciousorder - from files 20160921_1664afae318573894e850f85ff412d64.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash2       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1  = " \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s2  = "\"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3  = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii
    $s4  = "\"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s5  = "n fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"I" ascii
    $s6  = "USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(functi" ascii
    $s7  = "on fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s8  = "k(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s10 = "\"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s11 = "rn \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s12 = " \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s13 = "k(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\"" ascii
    $s14 = "urn \"Oh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s15 = "uck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s16 = "tion fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return" ascii
    $s17 = "k(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"RAi" ascii
    $s18 = "fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IK" ascii
    $s19 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s20 = "Sf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}