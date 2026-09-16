rule _20160921_6db2cb585eb933d83d07b47d979b00ec_20160921_afb633ee817d_5376 {
  meta:
    description = "datamaliciousorder - from files 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash3       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"M" ascii
    $s2 = "turn \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})()," ascii
    $s3 = "){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";}" ascii
    $s4 = "n fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s5 = "rn \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}