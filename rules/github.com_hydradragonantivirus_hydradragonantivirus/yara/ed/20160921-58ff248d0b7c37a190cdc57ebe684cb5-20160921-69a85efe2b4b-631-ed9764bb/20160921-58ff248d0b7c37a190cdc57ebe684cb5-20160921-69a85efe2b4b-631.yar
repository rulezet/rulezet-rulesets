rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_69a85efe2b4b_631 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1  = "\"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s2  = "n \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(fun" ascii
    $s3  = "r\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function " ascii
    $s4  = "rn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s5  = " \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s6  = "return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})" ascii
    $s7  = "})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck" ascii
    $s8  = "uck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\"" ascii
    $s9  = "ck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf" ascii
    $s10 = "nction fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){retu" ascii
    $s11 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s12 = "Vf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"XFd\";})(),(function" ascii
    $s13 = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s14 = "eturn \"Et\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s15 = "ion fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s16 = "eturn \"Ug\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s17 = "ck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs" ascii
    $s18 = ")(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck" ascii
    $s19 = "){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})" ascii
    $s20 = "\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}