rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_58ff248d0b7c_3476 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_dd42e850834f3af27a08edf609a699b5.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"
    hash4       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "rn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s3 = "tion fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "),(function fuck(){return \"We\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"OQr\";})(),(function fuck()" ascii
    $s5 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZLd" ascii
    $s6 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Vf\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}