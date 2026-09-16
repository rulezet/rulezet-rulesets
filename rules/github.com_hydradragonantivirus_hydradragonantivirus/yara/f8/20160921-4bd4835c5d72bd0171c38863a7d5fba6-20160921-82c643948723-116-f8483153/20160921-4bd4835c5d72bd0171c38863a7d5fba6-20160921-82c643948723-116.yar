rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_82c643948723_116 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"

  strings:
    $s1  = "uck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi" ascii
    $s2  = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3  = "fuck(){return \"Av\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s4  = "n \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5  = "nction fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retu" ascii
    $s6  = "(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s7  = "n fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s8  = "Pu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s9  = " \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s10 = "tion fuck(){return \"To\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s11 = "uck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm" ascii
    $s12 = "eturn \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s13 = "fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"U" ascii
    $s14 = "Sf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s15 = "})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuc" ascii
    $s16 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return" ascii
    $s17 = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})()" ascii
    $s18 = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s19 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s20 = "k(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}