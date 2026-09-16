rule _20160921_2111693a6587de2f8afee1834010d572_20160921_70fc4d2c06ba_4671 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash3       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"
    hash4       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s2 = "turn \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s3 = "on fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return " ascii
    $s4 = "ction fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retur" ascii
    $s5 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}