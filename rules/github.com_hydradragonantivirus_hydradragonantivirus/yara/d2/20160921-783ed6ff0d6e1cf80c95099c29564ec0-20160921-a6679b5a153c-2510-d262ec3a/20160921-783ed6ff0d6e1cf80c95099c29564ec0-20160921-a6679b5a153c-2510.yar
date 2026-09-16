rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_a6679b5a153c_2510 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"

  strings:
    $s1 = "rn \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s2 = "n \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(fun" ascii
    $s3 = "return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})()" ascii
    $s4 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s5 = "ion fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s6 = "function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){re" ascii
    $s7 = "eturn \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s8 = "on fuck(){return \"Vf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}