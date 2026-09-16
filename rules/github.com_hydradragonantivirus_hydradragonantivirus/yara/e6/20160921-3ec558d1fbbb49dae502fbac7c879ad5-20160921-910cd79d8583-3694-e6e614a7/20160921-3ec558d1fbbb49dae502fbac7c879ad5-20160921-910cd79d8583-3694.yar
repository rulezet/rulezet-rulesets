rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_3694 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash3       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s2 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii
    $s3 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"D" ascii
    $s4 = "eturn \"Jg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(" ascii
    $s5 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retur" ascii
    $s6 = "{return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}