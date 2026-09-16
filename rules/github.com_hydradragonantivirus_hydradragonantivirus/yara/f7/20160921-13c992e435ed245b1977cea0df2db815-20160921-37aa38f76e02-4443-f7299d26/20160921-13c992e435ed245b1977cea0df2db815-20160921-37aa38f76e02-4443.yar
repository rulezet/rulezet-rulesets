rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_37aa38f76e02_4443 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_37aa38f76e02afb64903280105ce4597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"

  strings:
    $s1 = "turn \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s2 = "p\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return" ascii
    $s4 = "n \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s5 = "){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}