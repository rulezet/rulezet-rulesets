rule _20160921_8f9ae4533bfbaedf1feae61032904250_20160921_cd62091b5494_5535 {
  meta:
    description = "datamaliciousorder - from files 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash2       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash3       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"
    hash4       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii
    $s2 = " fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"" ascii
    $s3 = "rn \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s4 = "{return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(" ascii
    $s5 = "fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NK" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}