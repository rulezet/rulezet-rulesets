rule _20160921_3b2083afdb57ae7e611f6f42c6787c73_20160921_b6523fd99592_1198 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"

  strings:
    $s1  = "y\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(functio" ascii
    $s2  = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na" ascii
    $s3  = "ion fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4  = "\"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s5  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";}" ascii
    $s6  = "return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7  = "\"Zy\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s8  = "turn \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s9  = "return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s10 = "eturn \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s11 = " \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s12 = "(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s13 = "ck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo" ascii
    $s14 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s15 = ")(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii
    $s16 = " \"XFd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}