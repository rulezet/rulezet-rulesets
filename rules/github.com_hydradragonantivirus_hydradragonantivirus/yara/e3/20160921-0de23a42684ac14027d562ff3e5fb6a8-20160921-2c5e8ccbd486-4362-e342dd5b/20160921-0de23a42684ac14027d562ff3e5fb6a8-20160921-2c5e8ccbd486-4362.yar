rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_2c5e8ccbd486_4362 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"

  strings:
    $s1 = "(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s2 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return " ascii
    $s3 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s4 = "eturn \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5 = " \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}