rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_5025 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"
    hash4       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "k(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";}" ascii
    $s2 = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s3 = " \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s4 = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s5 = "Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}