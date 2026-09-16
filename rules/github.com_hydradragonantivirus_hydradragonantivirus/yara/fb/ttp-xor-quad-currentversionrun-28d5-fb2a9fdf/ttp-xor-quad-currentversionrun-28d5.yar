rule TTP_XOR_QUAD_CurrentVersionRun_28d5 {
  strings:
    $key_28d5 = { 7b ba [2] 5f b4 [2] 74 98 [2] 5a ba [2] 4e a1 [2] 41 bb [2] 5f a6 [2] 5d a7 [2] 46 a1 [2] 5a a6 [2] 46 89 }

  condition:
    any of them
}