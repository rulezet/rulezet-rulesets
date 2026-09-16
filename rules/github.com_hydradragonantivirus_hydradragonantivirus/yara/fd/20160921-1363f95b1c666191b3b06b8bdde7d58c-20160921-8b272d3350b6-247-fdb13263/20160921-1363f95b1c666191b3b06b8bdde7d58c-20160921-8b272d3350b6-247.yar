rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_8b272d3350b6_247 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"

  strings:
    $s1  = "\"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s2  = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function " ascii
    $s3  = "on fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4  = ";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fu" ascii
    $s5  = "uck(){return \"GWo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IR" ascii
    $s6  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(fun" ascii
    $s7  = "GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(functi" ascii
    $s8  = "eturn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s9  = "{return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(" ascii
    $s10 = "(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s11 = "(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";" ascii
    $s12 = "TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s13 = "})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fu" ascii
    $s14 = ",(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s15 = "ck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq" ascii
    $s16 = "return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s17 = ")(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(" ascii
    $s18 = "turn \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s19 = "fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GN" ascii
    $s20 = "i\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}