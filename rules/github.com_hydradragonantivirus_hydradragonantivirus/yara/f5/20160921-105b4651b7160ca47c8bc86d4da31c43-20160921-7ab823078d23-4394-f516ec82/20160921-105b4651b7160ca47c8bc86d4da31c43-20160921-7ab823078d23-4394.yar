rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_7ab823078d23_4394 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash4       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1 = "fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"X" ascii
    $s2 = ",(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){r" ascii
    $s3 = "function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){re" ascii
    $s4 = "Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s5 = "turn \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}