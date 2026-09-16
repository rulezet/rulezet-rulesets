rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_73b5a50d0662_363 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash3       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1  = "){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})" ascii
    $s2  = "(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";}" ascii
    $s3  = "ion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4  = "ion f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s5  = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";" ascii
    $s6  = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f00" ascii
    $s7  = "n \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s8  = "turn \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s9  = "nction f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s10 = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s11 = "tion f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s12 = "(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\"" ascii
    $s13 = "Xg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s14 = "\"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s15 = "n f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s16 = "Ij\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s17 = "n \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s18 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s19 = "nction f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s20 = "return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}