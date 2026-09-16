rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_759ae57c0ca1_1541 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1  = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";}" ascii
    $s2  = "ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(functi" ascii
    $s3  = ";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s4  = "return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s5  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s6  = "urn \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s7  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s8  = " fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s9  = ")(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s10 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Wo\";})(),(function fuck" ascii
    $s11 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){" ascii
    $s12 = "n \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}