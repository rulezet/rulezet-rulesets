rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_336aeb1d023b_4821 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "fuck(){return \"GWo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s2 = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii
    $s3 = "ction fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s4 = "fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs" ascii
    $s5 = "g\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}