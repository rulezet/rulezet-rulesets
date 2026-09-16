rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_3d472332b6f7_4908 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash4       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = "{return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})" ascii
    $s2 = "n f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3 = "{return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})()" ascii
    $s4 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s5 = "on f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}