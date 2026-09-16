rule _20160921_85f2776f4fe640d2373f51ddbc697659_20160921_c07f026b9458_650 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash2       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1  = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(" ascii
    $s2  = "\"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(func" ascii
    $s3  = "{return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})" ascii
    $s4  = "return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Py\";})()," ascii
    $s5  = ",(function fuck(){return \"UXf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s6  = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s7  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s8  = "tion fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s9  = "uck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe" ascii
    $s10 = "),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){" ascii
    $s11 = "rn \"Av\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s12 = "eturn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s13 = ";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s14 = "(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";}" ascii
    $s15 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})()," ascii
    $s16 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s17 = "turn \"Yk\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s18 = "function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s19 = "fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"P" ascii
    $s20 = "function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}