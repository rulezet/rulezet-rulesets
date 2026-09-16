rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_99220520e874_5323 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash3       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "uck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\"" ascii
    $s2 = "ck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";" ascii
    $s3 = "){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Z" ascii
    $s5 = "tion fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}