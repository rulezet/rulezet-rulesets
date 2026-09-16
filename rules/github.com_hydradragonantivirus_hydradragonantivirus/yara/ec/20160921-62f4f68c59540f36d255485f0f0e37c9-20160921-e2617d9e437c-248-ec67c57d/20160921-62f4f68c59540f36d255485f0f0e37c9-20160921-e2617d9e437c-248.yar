rule _20160921_62f4f68c59540f36d255485f0f0e37c9_20160921_e2617d9e437c_248 {
  meta:
    description = "datamaliciousorder - from files 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1  = "(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\"" ascii
    $s2  = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s3  = "k(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\"" ascii
    $s4  = "\"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s5  = "k(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";" ascii
    $s6  = "ck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np" ascii
    $s7  = "g\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s8  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s9  = "(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\"" ascii
    $s10 = "ck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np" ascii
    $s11 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s12 = "return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s13 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s14 = "ck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\"" ascii
    $s15 = "\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"YQt\";})(),(function" ascii
    $s16 = "ction fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s17 = " fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s18 = "rn \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s19 = "d\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function" ascii
    $s20 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}