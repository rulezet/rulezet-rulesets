rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_1c739a510b20_4324 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1 = "uck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn" ascii
    $s2 = "IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s3 = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s4 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s5 = "k(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}