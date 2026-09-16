rule _20160921_65ff2a70ce98d58243fbbdf4849b9c40_20160921_f156e377f521_230 {
  meta:
    description = "datamaliciousorder - from files 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash2       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1  = "rn \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s2  = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s3  = "{return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s4  = " fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"I" ascii
    $s5  = "rn \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(" ascii
    $s6  = " \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s7  = "k(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\"" ascii
    $s8  = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s9  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})()" ascii
    $s10 = "(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";" ascii
    $s11 = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s12 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s13 = "uck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UO" ascii
    $s14 = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s15 = "{return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"YQt\";})" ascii
    $s16 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s17 = "return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s18 = "(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){" ascii
    $s19 = "ck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\"" ascii
    $s20 = "return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}