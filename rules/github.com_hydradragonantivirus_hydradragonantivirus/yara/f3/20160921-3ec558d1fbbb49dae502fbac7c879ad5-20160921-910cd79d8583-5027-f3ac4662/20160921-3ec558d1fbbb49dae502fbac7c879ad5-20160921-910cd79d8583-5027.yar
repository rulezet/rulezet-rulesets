rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_5027 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1 = "Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functi" ascii
    $s2 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){retur" ascii
    $s3 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})()" ascii
    $s5 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Et\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}