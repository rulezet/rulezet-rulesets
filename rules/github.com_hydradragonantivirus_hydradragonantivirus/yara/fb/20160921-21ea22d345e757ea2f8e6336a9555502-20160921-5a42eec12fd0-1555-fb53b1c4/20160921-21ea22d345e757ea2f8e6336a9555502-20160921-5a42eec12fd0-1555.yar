rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_5a42eec12fd0_1555 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"

  strings:
    $s1  = "(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})" ascii
    $s2  = "eturn \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s3  = "n \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s4  = "\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s5  = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s6  = "n fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"I" ascii
    $s7  = " \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(funct" ascii
    $s8  = "fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"US" ascii
    $s9  = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(" ascii
    $s10 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s11 = ",(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){" ascii
    $s12 = "uck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UO" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}