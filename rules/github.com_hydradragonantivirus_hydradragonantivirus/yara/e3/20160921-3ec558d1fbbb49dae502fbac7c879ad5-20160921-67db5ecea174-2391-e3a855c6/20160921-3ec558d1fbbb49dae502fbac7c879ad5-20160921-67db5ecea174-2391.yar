rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_67db5ecea174_2391 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash3       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash4       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1 = "r\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function" ascii
    $s2 = "){return \"AUx\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";" ascii
    $s3 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"" ascii
    $s4 = "ck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\"" ascii
    $s5 = "rn \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\";})(),(fun" ascii
    $s6 = "unction fuck(){return \"Av\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s7 = "u\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s8 = "{return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ar\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}