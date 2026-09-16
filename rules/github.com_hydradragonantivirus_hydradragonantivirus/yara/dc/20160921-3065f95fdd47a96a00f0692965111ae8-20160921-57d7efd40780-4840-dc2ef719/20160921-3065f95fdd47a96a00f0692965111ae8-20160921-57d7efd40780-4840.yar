rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_57d7efd40780_4840 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1 = "k(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\"" ascii
    $s2 = "YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s3 = "(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";" ascii
    $s4 = "urn \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s5 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}