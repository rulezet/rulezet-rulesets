rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_22fd683e7973_4556 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash3       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash4       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1 = "return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s2 = "r\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function " ascii
    $s3 = "Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function " ascii
    $s4 = "uck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\"" ascii
    $s5 = "fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}