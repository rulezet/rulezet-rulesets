rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_91424e3b4f10_4580 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash3       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash4       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(functi" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retu" ascii
    $s3 = "(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s4 = "rn \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s5 = "){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}