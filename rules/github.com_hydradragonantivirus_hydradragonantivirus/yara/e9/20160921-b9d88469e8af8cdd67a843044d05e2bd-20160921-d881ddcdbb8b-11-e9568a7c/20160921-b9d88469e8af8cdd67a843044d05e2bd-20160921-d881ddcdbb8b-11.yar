rule _20160921_b9d88469e8af8cdd67a843044d05e2bd_20160921_d881ddcdbb8b_11 {
  meta:
    description = "datamaliciousorder - from files 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash2       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1  = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Qh\";})(),(fu" ascii
    $s2  = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){" ascii
    $s3  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s4  = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s5  = "function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){re" ascii
    $s6  = "\"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"CCb\";})(),(func" ascii
    $s7  = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s8  = "n \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s9  = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s10 = "nction fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s11 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IOs\";})(),(function fu" ascii
    $s12 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJ" ascii
    $s13 = "{return \"UXf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})" ascii
    $s14 = "ck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\"" ascii
    $s15 = "),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){" ascii
    $s16 = "uck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IK" ascii
    $s17 = "n \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s18 = "urn \"YQt\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s19 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii
    $s20 = "return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}