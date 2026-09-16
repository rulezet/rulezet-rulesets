rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_93920c7f8d8d_1679 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1  = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s2  = "{return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";}" ascii
    $s3  = "(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(" ascii
    $s4  = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s5  = "fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LG" ascii
    $s6  = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s7  = " \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s8  = "return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s9  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){re" ascii
    $s10 = "{return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s11 = "y\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}