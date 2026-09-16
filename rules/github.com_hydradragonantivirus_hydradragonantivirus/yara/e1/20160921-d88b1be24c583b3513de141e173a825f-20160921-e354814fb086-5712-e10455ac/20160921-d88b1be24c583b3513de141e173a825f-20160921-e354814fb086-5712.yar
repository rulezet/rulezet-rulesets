rule _20160921_d88b1be24c583b3513de141e173a825f_20160921_e354814fb086_5712 {
  meta:
    description = "datamaliciousorder - from files 20160921_d88b1be24c583b3513de141e173a825f.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(" ascii
    $s2 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii
    $s3 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";}" ascii
    $s4 = " \"QTc\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s5 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}