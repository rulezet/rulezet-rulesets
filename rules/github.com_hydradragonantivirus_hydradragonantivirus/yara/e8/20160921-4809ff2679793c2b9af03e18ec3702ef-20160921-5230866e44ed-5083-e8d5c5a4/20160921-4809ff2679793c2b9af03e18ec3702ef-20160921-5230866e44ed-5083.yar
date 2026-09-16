rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_5230866e44ed_5083 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_5230866e44eda4e054d929933fdfdae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"

  strings:
    $s1 = "turn \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})()," ascii
    $s2 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){ret" ascii
    $s3 = "return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s4 = "n fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s5 = "ck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}