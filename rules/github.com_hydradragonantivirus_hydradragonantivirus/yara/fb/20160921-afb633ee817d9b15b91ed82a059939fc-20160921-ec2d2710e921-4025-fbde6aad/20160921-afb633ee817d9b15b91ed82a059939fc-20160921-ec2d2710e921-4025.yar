rule _20160921_afb633ee817d9b15b91ed82a059939fc_20160921_ec2d2710e921_4025 {
  meta:
    description = "datamaliciousorder - from files 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "rn \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s2 = "ion fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s3 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s4 = "(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Av\";})" ascii
    $s5 = "return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s6 = "(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}