rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_122 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"

  strings:
    $s1  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XHj\";})" ascii
    $s2  = "fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s3  = "})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck" ascii
    $s4  = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s5  = "(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){re" ascii
    $s6  = "ck(){return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s7  = "ck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\"" ascii
    $s8  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s9  = "on fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"" ascii
    $s10 = "s\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s11 = "){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";}" ascii
    $s12 = "k(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";" ascii
    $s13 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s14 = "){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})" ascii
    $s15 = "){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"OPz\";}" ascii
    $s16 = "fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MU" ascii
    $s17 = "turn \"GWo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s18 = "\"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(func" ascii
    $s19 = "rn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(fu" ascii
    $s20 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}