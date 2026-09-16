rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_a96b471e778a_3810 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})" ascii
    $s2 = "ck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Fv" ascii
    $s3 = "z\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function" ascii
    $s4 = "r\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s5 = " fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"E" ascii
    $s6 = "){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}