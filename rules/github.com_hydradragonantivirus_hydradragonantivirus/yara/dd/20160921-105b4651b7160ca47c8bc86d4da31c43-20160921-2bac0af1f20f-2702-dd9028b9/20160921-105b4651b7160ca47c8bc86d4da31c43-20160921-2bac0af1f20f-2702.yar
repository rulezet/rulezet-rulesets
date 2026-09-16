rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_2bac0af1f20f_2702 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"

  strings:
    $s1 = ")(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii
    $s2 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Wo0\";})(),(" ascii
    $s3 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s4 = "Bg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s5 = "n fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return " ascii
    $s6 = "urn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})()," ascii
    $s7 = "){return \"XCr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}