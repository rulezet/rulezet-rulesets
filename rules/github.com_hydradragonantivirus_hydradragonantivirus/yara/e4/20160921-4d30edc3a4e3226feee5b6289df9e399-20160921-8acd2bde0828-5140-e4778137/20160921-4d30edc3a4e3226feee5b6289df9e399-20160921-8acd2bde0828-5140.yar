rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_8acd2bde0828_5140 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"

  strings:
    $s1 = "(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";" ascii
    $s2 = " \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(funct" ascii
    $s3 = "uck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo" ascii
    $s4 = "\"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(funct" ascii
    $s5 = " \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}