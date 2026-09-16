rule _20160921_2111693a6587de2f8afee1834010d572_20160921_7c37cf57d8ed_4672 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash3       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash4       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"

  strings:
    $s1 = "n \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s2 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"V" ascii
    $s3 = "eturn \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s4 = "ck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm" ascii
    $s5 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}