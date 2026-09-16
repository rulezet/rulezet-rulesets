rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_be4748da0160_4568 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "k(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\"" ascii
    $s2 = "uck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "rn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(fu" ascii
    $s4 = "Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s5 = "k(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}