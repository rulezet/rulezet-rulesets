rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_d82f64233994_4891 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s2 = "{return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(" ascii
    $s3 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){retu" ascii
    $s4 = "f\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function" ascii
    $s5 = "eturn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}