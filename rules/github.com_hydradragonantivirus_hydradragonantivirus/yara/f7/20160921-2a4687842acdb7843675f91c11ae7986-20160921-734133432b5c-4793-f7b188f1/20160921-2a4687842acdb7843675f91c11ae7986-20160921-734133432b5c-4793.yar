rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_734133432b5c_4793 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash3       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"
    hash4       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "k(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s2 = "){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";" ascii
    $s3 = "eturn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s4 = "{return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}