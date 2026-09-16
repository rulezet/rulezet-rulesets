rule _20160921_acc098eb35e159f33783b155bb8929cb_20160921_e2cf0a733063_3113 {
  meta:
    description = "datamaliciousorder - from files 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash2       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"
    hash3       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1 = "ction fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s3 = "urn \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s4 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s5 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"" ascii
    $s6 = "eturn \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})()" ascii
    $s7 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}