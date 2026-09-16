rule _20160921_bd40742bedf80aa0091b1fafd0a7ba4b_20160921_d0ae6acc5cc4_5663 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "fuck(){return \"Fv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQ" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s3 = "rn \"Fv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s4 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\"" ascii
    $s5 = "\"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}