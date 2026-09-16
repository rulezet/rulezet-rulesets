rule _20160921_063094039ef79437a260d3dde960797a_20160921_0a01ee7cfd67_3251 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"

  strings:
    $s1 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s2 = "function fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s3 = "eturn \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})()," ascii
    $s4 = "return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})" ascii
    $s5 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}