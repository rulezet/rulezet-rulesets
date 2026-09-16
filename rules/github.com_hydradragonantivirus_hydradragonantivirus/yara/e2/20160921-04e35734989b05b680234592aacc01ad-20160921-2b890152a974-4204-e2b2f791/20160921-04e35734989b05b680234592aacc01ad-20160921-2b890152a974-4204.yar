rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_4204 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash4       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"

  strings:
    $s1 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s2 = "uck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs" ascii
    $s3 = "on fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"" ascii
    $s4 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){ret" ascii
    $s5 = "})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}