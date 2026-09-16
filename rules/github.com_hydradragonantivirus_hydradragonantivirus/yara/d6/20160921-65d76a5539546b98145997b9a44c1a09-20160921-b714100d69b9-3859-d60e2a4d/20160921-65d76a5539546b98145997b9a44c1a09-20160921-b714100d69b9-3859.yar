rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_b714100d69b9_3859 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = ";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuc" ascii
    $s2 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"QTc\";})(),(function fuc" ascii
    $s3 = "urn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s4 = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5 = "on fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6 = "fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}