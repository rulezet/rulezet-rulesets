rule _20160921_063094039ef79437a260d3dde960797a_20160921_78bd4256ddc0_4253 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash3       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "){return \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})" ascii
    $s2 = "function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s3 = "),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){" ascii
    $s4 = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retu" ascii
    $s5 = "ck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}