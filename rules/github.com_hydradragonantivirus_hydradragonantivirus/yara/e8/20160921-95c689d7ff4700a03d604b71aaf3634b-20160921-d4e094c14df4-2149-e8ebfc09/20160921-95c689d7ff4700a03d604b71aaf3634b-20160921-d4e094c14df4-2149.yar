rule _20160921_95c689d7ff4700a03d604b71aaf3634b_20160921_d4e094c14df4_2149 {
  meta:
    description = "datamaliciousorder - from files 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash2       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"

  strings:
    $s1 = "(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s2 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return " ascii
    $s3 = "eturn \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()," ascii
    $s4 = "(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(" ascii
    $s5 = " \"Qh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s6 = " fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh" ascii
    $s7 = "function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s8 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QT" ascii
    $s9 = " \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}