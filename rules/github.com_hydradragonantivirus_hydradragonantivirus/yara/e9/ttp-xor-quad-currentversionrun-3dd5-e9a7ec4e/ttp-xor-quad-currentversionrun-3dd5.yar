rule TTP_XOR_QUAD_CurrentVersionRun_3dd5 {
  strings:
    $key_3dd5 = { 6e ba [2] 4a b4 [2] 61 98 [2] 4f ba [2] 5b a1 [2] 54 bb [2] 4a a6 [2] 48 a7 [2] 53 a1 [2] 4f a6 [2] 53 89 }

  condition:
    any of them
}