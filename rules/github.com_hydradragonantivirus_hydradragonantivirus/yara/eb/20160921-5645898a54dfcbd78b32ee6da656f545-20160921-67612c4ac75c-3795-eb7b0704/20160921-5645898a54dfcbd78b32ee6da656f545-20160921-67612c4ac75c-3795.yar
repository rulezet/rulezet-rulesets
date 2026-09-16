rule _20160921_5645898a54dfcbd78b32ee6da656f545_20160921_67612c4ac75c_3795 {
  meta:
    description = "datamaliciousorder - from files 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash2       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"

  strings:
    $s1 = "nction fuck(){return \"DWe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s2 = "fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx" ascii
    $s3 = "turn \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(f" ascii
    $s4 = "tion fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s5 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck" ascii
    $s6 = "tion fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}