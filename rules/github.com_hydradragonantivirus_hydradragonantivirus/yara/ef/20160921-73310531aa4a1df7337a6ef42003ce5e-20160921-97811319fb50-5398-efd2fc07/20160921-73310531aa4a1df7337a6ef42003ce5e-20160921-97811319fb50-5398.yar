rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_97811319fb50_5398 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash3       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s2 = " fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"" ascii
    $s3 = "{return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})" ascii
    $s4 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s5 = "n \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"MUs\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}