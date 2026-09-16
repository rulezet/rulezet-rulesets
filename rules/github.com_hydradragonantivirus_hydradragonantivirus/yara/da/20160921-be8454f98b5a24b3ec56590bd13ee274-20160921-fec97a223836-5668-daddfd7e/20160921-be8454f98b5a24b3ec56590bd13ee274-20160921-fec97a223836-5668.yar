rule _20160921_be8454f98b5a24b3ec56590bd13ee274_20160921_fec97a223836_5668 {
  meta:
    description = "datamaliciousorder - from files 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik" ascii
    $s2 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"O" ascii
    $s3 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s4 = "urn \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s5 = "(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}