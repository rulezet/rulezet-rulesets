rule _20160921_468b13a80ecc75cd21428202c521ca1d_20160921_62f4f68c5954_5066 {
  meta:
    description = "datamaliciousorder - from files 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash2       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s2 = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"" ascii
    $s3 = "{return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})" ascii
    $s4 = "){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";" ascii
    $s5 = "n \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}