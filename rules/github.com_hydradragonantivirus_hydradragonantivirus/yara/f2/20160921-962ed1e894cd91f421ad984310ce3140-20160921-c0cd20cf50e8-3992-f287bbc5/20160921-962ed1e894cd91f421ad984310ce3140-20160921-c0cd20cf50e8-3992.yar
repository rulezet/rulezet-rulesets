rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_c0cd20cf50e8_3992 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s2 = "{return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s3 = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck()" ascii
    $s4 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fu" ascii
    $s5 = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){r" ascii
    $s6 = "{return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}