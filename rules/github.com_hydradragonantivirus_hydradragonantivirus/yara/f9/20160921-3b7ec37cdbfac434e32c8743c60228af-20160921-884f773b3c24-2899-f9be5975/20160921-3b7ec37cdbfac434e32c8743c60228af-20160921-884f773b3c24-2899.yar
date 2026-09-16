rule _20160921_3b7ec37cdbfac434e32c8743c60228af_20160921_884f773b3c24_2899 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash3       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"

  strings:
    $s1 = "ck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq" ascii
    $s2 = "turn \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s3 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s5 = "),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s6 = "){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";}" ascii
    $s7 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}