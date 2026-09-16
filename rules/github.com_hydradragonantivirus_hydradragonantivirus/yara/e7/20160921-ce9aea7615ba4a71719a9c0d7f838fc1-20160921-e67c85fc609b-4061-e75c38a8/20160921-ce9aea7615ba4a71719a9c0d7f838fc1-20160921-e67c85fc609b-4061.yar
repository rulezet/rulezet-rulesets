rule _20160921_ce9aea7615ba4a71719a9c0d7f838fc1_20160921_e67c85fc609b_4061 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1 = "})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s2 = "urn \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s3 = "{return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})" ascii
    $s4 = "uck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb" ascii
    $s5 = "\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s6 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}