rule _20160921_20daf816cda5af37e984359023f15db2_20160921_70d636d209e6_3505 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash3       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash4       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s2 = "urn \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(fu" ascii
    $s3 = "on fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"X" ascii
    $s4 = "){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s5 = ",(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){re" ascii
    $s6 = "YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}