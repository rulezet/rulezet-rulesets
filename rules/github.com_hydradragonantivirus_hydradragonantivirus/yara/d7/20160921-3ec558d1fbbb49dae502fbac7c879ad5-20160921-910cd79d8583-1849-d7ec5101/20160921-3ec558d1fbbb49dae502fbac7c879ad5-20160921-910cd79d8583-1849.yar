rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_1849 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash4       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"

  strings:
    $s1  = "function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2  = "rn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s3  = "eturn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s4  = "ck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s5  = "Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s6  = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(functi" ascii
    $s7  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return" ascii
    $s8  = "return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})()," ascii
    $s9  = "n fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Y" ascii
    $s10 = ",(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}