rule _20160921_e2617d9e437c12b61ada4700f8e426b8_20160921_e354814fb086_4075 {
  meta:
    description = "datamaliciousorder - from files 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(" ascii
    $s2 = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Y" ascii
    $s3 = "(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";" ascii
    $s4 = "(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";}" ascii
    $s5 = ")(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s6 = "DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}