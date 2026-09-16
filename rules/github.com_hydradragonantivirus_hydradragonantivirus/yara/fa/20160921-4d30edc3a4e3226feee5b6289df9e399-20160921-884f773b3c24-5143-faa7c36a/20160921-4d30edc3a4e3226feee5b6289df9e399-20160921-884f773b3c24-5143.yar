rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_884f773b3c24_5143 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1 = "urn \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s2 = "rn \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(func" ascii
    $s3 = "eturn \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s4 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}