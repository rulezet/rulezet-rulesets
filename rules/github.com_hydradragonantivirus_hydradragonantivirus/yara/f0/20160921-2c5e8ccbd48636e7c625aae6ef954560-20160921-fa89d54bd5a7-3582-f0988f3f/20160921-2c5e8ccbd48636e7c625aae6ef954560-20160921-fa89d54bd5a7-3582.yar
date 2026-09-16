rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_fa89d54bd5a7_3582 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = " fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"A" ascii
    $s2 = "{return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})" ascii
    $s3 = "ck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";" ascii
    $s4 = "rn \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s5 = "return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})()," ascii
    $s6 = "n \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}