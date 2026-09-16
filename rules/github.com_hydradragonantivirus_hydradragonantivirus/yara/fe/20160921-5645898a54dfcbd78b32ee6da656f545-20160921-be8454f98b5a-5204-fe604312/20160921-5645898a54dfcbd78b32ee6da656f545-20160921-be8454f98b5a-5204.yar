rule _20160921_5645898a54dfcbd78b32ee6da656f545_20160921_be8454f98b5a_5204 {
  meta:
    description = "datamaliciousorder - from files 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1 = "n \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s2 = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\"" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s4 = "(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s5 = "ck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}