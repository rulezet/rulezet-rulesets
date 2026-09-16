rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_336aeb1d023b_272 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash3       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1  = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){" ascii
    $s2  = "k(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\"" ascii
    $s3  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function f" ascii
    $s4  = "urn \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s5  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"M" ascii
    $s6  = "MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s7  = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck" ascii
    $s8  = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fu" ascii
    $s9  = "Ui\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s10 = ";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function f" ascii
    $s11 = "i\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s12 = "urn \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(" ascii
    $s13 = "f\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function " ascii
    $s14 = "urn \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s15 = "f\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s16 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s17 = "turn \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})()" ascii
    $s18 = "k(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\"" ascii
    $s19 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s20 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}