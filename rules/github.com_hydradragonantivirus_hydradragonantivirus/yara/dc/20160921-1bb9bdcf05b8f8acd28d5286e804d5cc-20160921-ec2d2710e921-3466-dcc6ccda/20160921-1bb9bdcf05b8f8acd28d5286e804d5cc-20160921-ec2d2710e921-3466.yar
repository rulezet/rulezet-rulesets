rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_ec2d2710e921_3466 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = " \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s3 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){" ascii
    $s4 = "{return \"ZWu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retu" ascii
    $s6 = "k(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}