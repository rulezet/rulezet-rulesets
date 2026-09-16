rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_30902cdec8af_321 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash3       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"

  strings:
    $s1  = "turn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s2  = "return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s3  = "Bg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(functio" ascii
    $s4  = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s5  = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s6  = "rn \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(f" ascii
    $s7  = "n \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s8  = "g\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s9  = "){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})" ascii
    $s10 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs" ascii
    $s11 = "rn \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s12 = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s13 = "MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s14 = "rn \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s15 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s16 = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s17 = "ion fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s18 = "ck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu" ascii
    $s19 = "turn \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s20 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ve" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}