rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_74a9afe189b5_5389 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash3       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "tion fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2 = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3 = "\"Jo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s4 = "(){return \"Wo0\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s5 = "n \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}