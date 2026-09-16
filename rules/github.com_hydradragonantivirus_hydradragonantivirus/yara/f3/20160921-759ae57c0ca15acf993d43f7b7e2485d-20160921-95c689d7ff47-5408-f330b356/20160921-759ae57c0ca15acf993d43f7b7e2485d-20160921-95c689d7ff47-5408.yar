rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_95c689d7ff47_5408 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s2 = "(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"OQr\";" ascii
    $s3 = "eturn \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(f" ascii
    $s4 = "unction fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){retu" ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}