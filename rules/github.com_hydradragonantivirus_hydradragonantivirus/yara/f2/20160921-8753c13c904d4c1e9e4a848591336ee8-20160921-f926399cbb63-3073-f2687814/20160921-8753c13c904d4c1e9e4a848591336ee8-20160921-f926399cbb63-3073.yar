rule _20160921_8753c13c904d4c1e9e4a848591336ee8_20160921_f926399cbb63_3073 {
  meta:
    description = "datamaliciousorder - from files 20160921_8753c13c904d4c1e9e4a848591336ee8.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = " \"DHd\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(func" ascii
    $s2 = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s3 = "return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s4 = "),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s5 = "n \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s6 = "uck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s7 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}