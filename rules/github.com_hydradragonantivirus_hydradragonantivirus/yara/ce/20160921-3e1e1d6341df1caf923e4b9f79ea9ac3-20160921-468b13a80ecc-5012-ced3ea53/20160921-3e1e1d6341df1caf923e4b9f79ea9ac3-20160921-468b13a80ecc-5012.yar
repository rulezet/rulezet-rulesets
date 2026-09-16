rule _20160921_3e1e1d6341df1caf923e4b9f79ea9ac3_20160921_468b13a80ecc_5012 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash2       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash3       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})" ascii
    $s2 = "tion fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s3 = "{return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";}" ascii
    $s4 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5 = "g\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}