rule _20160921_58b4526aa2dc68b6db4250cf3153d1c5_20160921_95c689d7ff47_2975 {
  meta:
    description = "datamaliciousorder - from files 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash2       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"

  strings:
    $s1 = "Bg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(functio" ascii
    $s2 = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s3 = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(" ascii
    $s5 = "\"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(funct" ascii
    $s6 = "fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s7 = "\"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}