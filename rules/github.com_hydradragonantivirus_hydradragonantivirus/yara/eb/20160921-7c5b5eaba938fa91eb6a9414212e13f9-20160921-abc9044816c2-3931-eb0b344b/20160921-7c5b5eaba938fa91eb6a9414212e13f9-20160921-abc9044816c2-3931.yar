rule _20160921_7c5b5eaba938fa91eb6a9414212e13f9_20160921_abc9044816c2_3931 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash2       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1 = "})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(func" ascii
    $s3 = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s4 = "urn \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(f" ascii
    $s5 = "{return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Av\";})()" ascii
    $s6 = "ck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}