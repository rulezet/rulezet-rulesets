rule _20160921_f5230fc58405f25233bda6815654bd6e_20160921_fc08be0621d4_5730 {
  meta:
    description = "datamaliciousorder - from files 20160921_f5230fc58405f25233bda6815654bd6e.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\"" ascii
    $s2 = " \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3 = "{return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})" ascii
    $s4 = " fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"J" ascii
    $s5 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}