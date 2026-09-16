rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_8ed14dc63f5b_3531 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s2 = "nction f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s3 = "\"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "eturn \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(" ascii
    $s5 = "Ts\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s6 = "f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}