rule _20160921_50b14bf13c50bc31f09e3c583e1d422d_20160921_dbc1b5f3d038_3767 {
  meta:
    description = "datamaliciousorder - from files 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash2       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"

  strings:
    $s1 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo" ascii
    $s2 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";}" ascii
    $s3 = "{return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s4 = "Qt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5 = "Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s6 = "n \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}