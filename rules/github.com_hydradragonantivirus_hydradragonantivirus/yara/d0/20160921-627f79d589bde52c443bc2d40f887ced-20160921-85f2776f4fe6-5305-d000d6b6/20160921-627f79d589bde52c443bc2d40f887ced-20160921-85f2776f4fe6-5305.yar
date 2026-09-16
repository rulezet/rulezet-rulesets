rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_85f2776f4fe6_5305 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck" ascii
    $s2 = " fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"U" ascii
    $s3 = "urn \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s4 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(" ascii
    $s5 = " fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}