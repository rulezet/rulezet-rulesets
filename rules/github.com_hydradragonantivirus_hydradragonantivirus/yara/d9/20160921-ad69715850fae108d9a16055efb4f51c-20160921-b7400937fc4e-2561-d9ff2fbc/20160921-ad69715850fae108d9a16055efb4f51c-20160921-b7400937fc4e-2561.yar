rule _20160921_ad69715850fae108d9a16055efb4f51c_20160921_b7400937fc4e_2561 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash3       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";}" ascii
    $s2 = "return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(" ascii
    $s3 = "0(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s5 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s6 = " f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s7 = " \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s8 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}