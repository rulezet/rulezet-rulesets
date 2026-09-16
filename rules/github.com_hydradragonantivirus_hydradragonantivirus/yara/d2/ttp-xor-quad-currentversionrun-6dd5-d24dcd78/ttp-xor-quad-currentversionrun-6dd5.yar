rule TTP_XOR_QUAD_CurrentVersionRun_6dd5 {
  strings:
    $key_6dd5 = { 3e ba [2] 1a b4 [2] 31 98 [2] 1f ba [2] 0b a1 [2] 04 bb [2] 1a a6 [2] 18 a7 [2] 03 a1 [2] 1f a6 [2] 03 89 }

  condition:
    any of them
}