rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_9ef73b9f4f78_5226 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";" ascii
    $s2 = "rn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s3 = "k(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})" ascii
    $s4 = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return" ascii
    $s5 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}