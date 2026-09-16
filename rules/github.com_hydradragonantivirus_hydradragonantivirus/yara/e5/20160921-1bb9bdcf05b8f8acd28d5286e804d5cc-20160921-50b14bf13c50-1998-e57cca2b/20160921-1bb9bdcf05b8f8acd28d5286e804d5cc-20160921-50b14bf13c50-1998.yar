rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_50b14bf13c50_1998 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash3       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = " fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){" ascii
    $s3 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(" ascii
    $s4 = "turn \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retu" ascii
    $s6 = "o0\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s7 = "){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Dc\";})(" ascii
    $s8 = "ion fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s9 = "function fuck(){return \"To\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}