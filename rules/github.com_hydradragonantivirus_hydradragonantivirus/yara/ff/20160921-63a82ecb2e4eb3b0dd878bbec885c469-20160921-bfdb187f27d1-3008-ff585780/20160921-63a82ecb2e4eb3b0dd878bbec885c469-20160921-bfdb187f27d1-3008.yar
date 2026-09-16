rule _20160921_63a82ecb2e4eb3b0dd878bbec885c469_20160921_bfdb187f27d1_3008 {
  meta:
    description = "datamaliciousorder - from files 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1 = "n fuck(){return \"To\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"I" ascii
    $s2 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s3 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s4 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck()" ascii
    $s5 = "n \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s6 = ";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s7 = ",(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}