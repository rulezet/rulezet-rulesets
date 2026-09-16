rule _20160921_5c25506bc44b50a0c8028dec6521139d_20160921_7c5b5eaba938_2460 {
  meta:
    description = "datamaliciousorder - from files 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = " \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(functi" ascii
    $s2 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})(),(function f" ascii
    $s3 = "r\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s4 = "on fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s5 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s6 = "n fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"O" ascii
    $s7 = "on fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s8 = "nction fuck(){return \"KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}