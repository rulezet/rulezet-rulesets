rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_5c25506bc44b_3638 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash3       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1 = "),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){" ascii
    $s2 = "function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s3 = ";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s4 = "IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s5 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){re" ascii
    $s6 = "\"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}