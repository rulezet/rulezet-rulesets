rule _20160921_d88b1be24c583b3513de141e173a825f_20160921_e78383c7f2f1_1931 {
  meta:
    description = "datamaliciousorder - from files 20160921_d88b1be24c583b3513de141e173a825f.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1  = "){return \"CCb\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";" ascii
    $s2  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return " ascii
    $s3  = "{return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(" ascii
    $s4  = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Wo0\";})(),(function" ascii
    $s5  = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s6  = "urn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s7  = "\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function" ascii
    $s8  = "ction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s9  = "(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii
    $s10 = "})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}