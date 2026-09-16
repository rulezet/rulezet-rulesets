rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_af22e174703e_606 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1  = "\"MIl\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2  = "k(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"FJs" ascii
    $s3  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s4  = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){" ascii
    $s5  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx" ascii
    $s6  = "n fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"P" ascii
    $s7  = "ck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi" ascii
    $s8  = "turn \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s9  = "uck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn" ascii
    $s10 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py" ascii
    $s11 = " \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(func" ascii
    $s12 = "k(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";" ascii
    $s13 = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){r" ascii
    $s14 = "uck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn" ascii
    $s15 = "){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})" ascii
    $s16 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s17 = " \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s18 = "PDf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s19 = "tion fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s20 = "n \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}