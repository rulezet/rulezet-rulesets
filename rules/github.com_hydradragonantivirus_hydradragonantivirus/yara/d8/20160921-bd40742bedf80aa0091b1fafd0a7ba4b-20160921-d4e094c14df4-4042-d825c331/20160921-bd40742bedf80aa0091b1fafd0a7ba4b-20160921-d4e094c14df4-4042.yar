rule _20160921_bd40742bedf80aa0091b1fafd0a7ba4b_20160921_d4e094c14df4_4042 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash2       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"

  strings:
    $s1 = "k(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s2 = "on fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s3 = "\"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(f" ascii
    $s6 = "){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}