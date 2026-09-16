rule _20160921_44880573519212a90b7d910319fc31d8_20160921_dc73cfa7a33e_5062 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = "n fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IP" ascii
    $s2 = "){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";}" ascii
    $s3 = "return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "ction fuck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s5 = " \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}