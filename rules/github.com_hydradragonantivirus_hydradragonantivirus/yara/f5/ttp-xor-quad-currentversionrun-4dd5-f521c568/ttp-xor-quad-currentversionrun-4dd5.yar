rule TTP_XOR_QUAD_CurrentVersionRun_4dd5 {
  strings:
    $key_4dd5 = { 1e ba [2] 3a b4 [2] 11 98 [2] 3f ba [2] 2b a1 [2] 24 bb [2] 3a a6 [2] 38 a7 [2] 23 a1 [2] 3f a6 [2] 23 89 }

  condition:
    any of them
}