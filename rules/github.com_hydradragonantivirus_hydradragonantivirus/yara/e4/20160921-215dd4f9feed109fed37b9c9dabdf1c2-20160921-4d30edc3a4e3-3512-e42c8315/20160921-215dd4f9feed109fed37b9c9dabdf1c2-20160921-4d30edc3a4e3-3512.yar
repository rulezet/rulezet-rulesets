rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_4d30edc3a4e3_3512 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"

  strings:
    $s1 = " \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s2 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s3 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s4 = " fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IR" ascii
    $s5 = " fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IR" ascii
    $s6 = "){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}