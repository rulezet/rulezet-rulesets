rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_bfdb187f27d1_3618 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1 = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s2 = "eturn \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})()," ascii
    $s3 = "),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s4 = "return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh" ascii
    $s6 = "tion fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}