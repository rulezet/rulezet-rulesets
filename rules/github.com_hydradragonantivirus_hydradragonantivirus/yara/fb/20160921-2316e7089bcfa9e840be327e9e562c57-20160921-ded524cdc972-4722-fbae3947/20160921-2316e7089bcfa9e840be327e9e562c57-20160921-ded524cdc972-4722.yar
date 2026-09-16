rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_ded524cdc972_4722 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "0(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = " \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(func" ascii
    $s3 = "i\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s4 = "unction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s5 = "f000(){return \"ZFe\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}