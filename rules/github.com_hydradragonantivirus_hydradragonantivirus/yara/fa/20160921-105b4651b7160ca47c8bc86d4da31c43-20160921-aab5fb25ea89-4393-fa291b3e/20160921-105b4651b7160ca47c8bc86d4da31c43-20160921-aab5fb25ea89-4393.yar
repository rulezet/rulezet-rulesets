rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_aab5fb25ea89_4393 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s3 = "\"Xw\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(funct" ascii
    $s4 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi" ascii
    $s5 = "n fuck(){return \"Sx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}