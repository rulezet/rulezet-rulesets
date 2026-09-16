rule _20160921_2111693a6587de2f8afee1834010d572_20160921_6db2cb585eb9_4669 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash3       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "rn \"Pc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Ar\";})(),(fu" ascii
    $s2 = "uck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UXf" ascii
    $s3 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s4 = "s\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s5 = "uck(){return \"QTc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}