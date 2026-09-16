rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_940fdd83fcdf_5010 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})" ascii
    $s4 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s5 = " fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}