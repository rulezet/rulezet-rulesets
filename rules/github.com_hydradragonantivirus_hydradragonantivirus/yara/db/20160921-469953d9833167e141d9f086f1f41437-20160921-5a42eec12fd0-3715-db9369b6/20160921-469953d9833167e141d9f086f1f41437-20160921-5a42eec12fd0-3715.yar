rule _20160921_469953d9833167e141d9f086f1f41437_20160921_5a42eec12fd0_3715 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"

  strings:
    $s1 = "){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";}" ascii
    $s2 = "unction fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){ret" ascii
    $s3 = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4 = "n \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s5 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\"" ascii
    $s6 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}